// P0-11 check: the SAME INSTANT written with different zone designators must yield ONE epoch value.
// Algorithm copied verbatim from the committed diff; tested against Date.parse as the reference.
const CANONICAL_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})$/;
const iq=(n,d)=>(n-(n%d))/d;
const leap=y=>y%4===0&&(y%100!==0||y%400===0);
const dim=(y,m)=>m===2?(leap(y)?29:28):(m===4||m===6||m===9||m===11?30:31);
function dfc(y,m,d){const sy=y-(m<=2?1:0);const era=sy<0?-1:iq(sy,400);const yoe=sy-era*400;
 const sm=m+(m>2?-3:9);const doy=iq(153*sm+2,5)+d-1;
 const doe=yoe*365+iq(yoe,4)-iq(yoe,100)+doy;return era*146097+doe-719468;}
function parseTime(v){
 if(typeof v!=="string")return NaN; if(!CANONICAL_INSTANT.test(v))return NaN;
 const dg=o=>+v[o], td=o=>dg(o)*10+dg(o+1);
 const year=dg(0)*1000+dg(1)*100+dg(2)*10+dg(3),month=td(5),day=td(8),hour=td(11),minute=td(14),second=td(17);
 const hasMs=v[19]===".";const ms=hasMs?dg(20)*100+dg(21)*10+dg(22):0;
 const zoneOffset=hasMs?23:19;
 let offsetMinutes=0;
 if(v[zoneOffset]!=="Z"){const oh=td(zoneOffset+1),om=td(zoneOffset+4);
  if(oh>23||om>59)return NaN;const sign=v[zoneOffset]==="+"?1:-1;offsetMinutes=sign*(oh*60+om);}
 if(month<1||month>12)return NaN; if(day<1||day>dim(year,month))return NaN;
 if(hour>23||minute>59)return NaN; if(second>59)return NaN;
 return dfc(year,month,day)*86400000+hour*3600000+minute*60000+second*1000+ms-offsetMinutes*60000;
}
const same=[["2026-07-14T12:00:00.000Z","2026-07-14T14:00:00.000+02:00","2026-07-14T07:00:00.000-05:00","2026-07-14T12:00:00.000+00:00"],
            ["2026-01-01T00:00:00.000Z","2026-01-01T05:30:00.000+05:30","2025-12-31T14:00:00.000-10:00"]];
let bad=0;
for(const grp of same){const vals=grp.map(parseTime);const ok=vals.every(v=>v===vals[0]);
 console.log((ok?"SAME  ":"DIFFER")+"  "+grp.join("  ==  ")+"  -> "+vals.join(", "));if(!ok)bad++;}
console.log("--- vs Date.parse (the reference for what these strings have always meant) ---");
for(const s of same.flat()){const m=parseTime(s),r=Date.parse(s);
 if(m!==r){console.log("MISMATCH "+s+"  mine="+m+" ref="+r+" delta="+(m-r));bad++;}}
console.log(bad?`FAIL: ${bad} problem(s)`:"OK: every group agrees internally AND matches Date.parse");
console.log("--- ANTI-VACUITY: the harness must be able to FAIL ---");
const wrong="2026-07-14T13:00:00.000+02:00"; // deliberately NOT the same instant
const wrongDiffers=parseTime(wrong)!==parseTime("2026-07-14T12:00:00.000Z");
console.log("a genuinely different instant differs: "+wrongDiffers);
console.log("--- malformed offsets must fail closed ---");
const malformed=["2026-07-14T12:00:00.000+24:00","2026-07-14T12:00:00.000+02:60","2026-07-14T12:00:00.000+2:00","2026-07-14T12:00:00.000 +02:00"];
for(const s of malformed)
 console.log("  "+JSON.stringify(s)+" -> "+(Number.isNaN(parseTime(s))?"NaN (refused)":"ACCEPTED  <-- LEAK"));
const malformedLeaks=malformed.filter(s=>!Number.isNaN(parseTime(s)));
if(bad!==0||!wrongDiffers||malformedLeaks.length!==0)process.exitCode=1;
