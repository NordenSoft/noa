/**
 * A tiny, zero-dependency evaluator for the JSON-Schema SUBSET the side-artifact schemas use.
 *
 * Why hand-rolled instead of a library: `noa-receipt` is deliberately zero-runtime-dependency and
 * hand-rolls its own strict validator (`src/schema.ts`) while ALSO shipping a machine-readable
 * `schema/*.schema.json` for external tooling. This package follows that convention — but goes one
 * step further so the two never drift: the SHIPPED `schema/*.schema.json` files ARE the enforced
 * structural validator, executed directly by this evaluator. There is no second, hand-written
 * validator to fall out of sync with the published schema.
 *
 * Supported keywords (everything the artifact schemas need, nothing more):
 *   $ref (local "#/$defs/<name>"), type (string | string[]), const, enum, pattern (on strings),
 *   minimum, maximum, properties, required, additionalProperties (false | subschema), items,
 *   minItems, oneOf. `additionalProperties` defaults to PERMISSIVE only if omitted — every artifact
 *   schema sets it to `false` explicitly (§6: additionalProperties:false at every level).
 */

export interface SchemaEvalResult {
  ok: boolean;
  errors: string[];
}

type Json = unknown;
interface SchemaNode {
  [k: string]: Json;
}

function typeName(v: Json): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v; // "object" | "string" | "number" | "boolean"
}

function matchesType(v: Json, t: string): boolean {
  switch (t) {
    case "object":
      return typeof v === "object" && v !== null && !Array.isArray(v);
    case "array":
      return Array.isArray(v);
    case "string":
      return typeof v === "string";
    case "integer":
      return typeof v === "number" && Number.isInteger(v) && Number.isSafeInteger(v);
    case "number":
      return typeof v === "number" && Number.isFinite(v);
    case "boolean":
      return typeof v === "boolean";
    case "null":
      return v === null;
    default:
      return false;
  }
}

function resolveRef(root: SchemaNode, ref: string): SchemaNode {
  // Only local "#/$defs/<name>" refs are supported.
  const m = /^#\/\$defs\/([A-Za-z0-9_-]+)$/.exec(ref);
  if (!m) throw new Error(`schema-eval: unsupported $ref "${ref}" (only #/$defs/<name>)`);
  const defs = root.$defs as Record<string, SchemaNode> | undefined;
  const target = defs?.[m[1]!];
  if (!target) throw new Error(`schema-eval: $ref target not found "${ref}"`);
  return target;
}

function evalNode(schema: SchemaNode, value: Json, root: SchemaNode, path: string, errors: string[]): void {
  if (typeof schema.$ref === "string") {
    evalNode(resolveRef(root, schema.$ref), value, root, path, errors);
    return;
  }

  // oneOf: value must validate against EXACTLY one subschema (discriminated unions).
  if (Array.isArray(schema.oneOf)) {
    let matched = 0;
    let lastErrs: string[] = [];
    for (const sub of schema.oneOf as SchemaNode[]) {
      const subErrs: string[] = [];
      evalNode(sub, value, root, path, subErrs);
      if (subErrs.length === 0) matched++;
      else lastErrs = subErrs;
    }
    if (matched !== 1) {
      errors.push(`${path}: matched ${matched} oneOf branches (expected exactly 1)${matched === 0 && lastErrs.length ? " — e.g. " + lastErrs[0] : ""}`);
    }
    return;
  }

  // type (single or union)
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? (schema.type as string[]) : [schema.type as string];
    if (!types.some((t) => matchesType(value, t))) {
      errors.push(`${path}: expected type ${types.join("|")}, got ${typeName(value)}`);
      return; // further keyword checks are meaningless on a type mismatch
    }
  }

  // const
  if ("const" in schema && value !== schema.const) {
    errors.push(`${path}: must equal ${JSON.stringify(schema.const)}`);
  }

  // enum
  if (Array.isArray(schema.enum) && !(schema.enum as Json[]).some((e) => e === value)) {
    errors.push(`${path}: must be one of ${JSON.stringify(schema.enum)}`);
  }

  // string pattern
  if (typeof schema.pattern === "string" && typeof value === "string") {
    if (!new RegExp(schema.pattern as string).test(value)) {
      errors.push(`${path}: does not match /${schema.pattern}/`);
    }
  }

  // number bounds
  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) errors.push(`${path}: < minimum ${schema.minimum}`);
    if (typeof schema.maximum === "number" && value > schema.maximum) errors.push(`${path}: > maximum ${schema.maximum}`);
  }

  // arrays
  if (Array.isArray(value)) {
    if (typeof schema.minItems === "number" && value.length < schema.minItems) {
      errors.push(`${path}: needs ≥${schema.minItems} items, got ${value.length}`);
    }
    if (schema.items && typeof schema.items === "object") {
      value.forEach((item, i) => evalNode(schema.items as SchemaNode, item, root, `${path}[${i}]`, errors));
    }
  }

  // objects
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const obj = value as Record<string, Json>;
    const props = (schema.properties as Record<string, SchemaNode> | undefined) ?? {};
    const required = (schema.required as string[] | undefined) ?? [];
    for (const r of required) {
      if (!Object.prototype.hasOwnProperty.call(obj, r)) errors.push(`${path}: missing required "${r}"`);
    }
    for (const k of Object.keys(obj)) {
      if (Object.prototype.hasOwnProperty.call(props, k)) {
        evalNode(props[k]!, obj[k], root, `${path}.${k}`, errors);
      } else if (schema.additionalProperties === false) {
        errors.push(`${path}: unknown property "${k}"`);
      } else if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
        evalNode(schema.additionalProperties as SchemaNode, obj[k], root, `${path}.${k}`, errors);
      }
    }
  }
}

/** Validate `value` against a JSON-Schema-subset document. */
export function evalSchema(schema: SchemaNode, value: Json): SchemaEvalResult {
  const errors: string[] = [];
  try {
    evalNode(schema, value, schema, "$", errors);
  } catch (e) {
    return { ok: false, errors: [`schema-eval error: ${(e as Error).message}`] };
  }
  return { ok: errors.length === 0, errors };
}
