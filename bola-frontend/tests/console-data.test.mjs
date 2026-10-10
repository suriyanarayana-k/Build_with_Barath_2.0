import assert from 'node:assert/strict';
import test from 'node:test';
import { readConsoleView, visibleEvents, riskText } from '../src/lib/console-data.ts';
const now=200000;
const events=[
 {id:1,occurred_at:now-30,subject_id:'client-1',record_id:'order-1',outcome:'allowed',explanation:'Owner verified'},
 {id:2,occurred_at:now-120,subject_id:'client-2',record_id:'order-2',outcome:'denied',explanation:'Ownership mismatch'},
 {id:3,occurred_at:now-7200,subject_id:'client-3',record_id:'order-3',outcome:'blocked',explanation:'Repeated unowned access'},
];
test('time range excludes old events without changing the loaded history',()=>{
 assert.deepEqual(visibleEvents(events,1,now).map(e=>e.id),[1,2]);
 assert.equal(events.length,3);
 assert.deepEqual(visibleEvents(events,24,now).map(e=>e.id),[1,2,3]);
});
test('subject, resource and explanation filters combine with outcome and time',()=>{
 assert.deepEqual(visibleEvents(events,24,now,'CLIENT-2','denied').map(e=>e.id),[2]);
 assert.deepEqual(visibleEvents(events,24,now,'order-2','allowed'),[]);
 assert.deepEqual(visibleEvents(events,24,now,'unowned').map(e=>e.id),[3]);
 assert.deepEqual(visibleEvents(events,1,now,'unowned'),[]);
});
test('unknown dashboard routes safely resolve to overview',()=>{
 assert.equal(readConsoleView('/dashboard/api-access'),'api-access');
 assert.equal(readConsoleView('/dashboard/usage'),'usage');
 assert.equal(readConsoleView('/dashboard/unknown'),'overview');
});
test('missing risk is not presented as zero and decimals remain explicit',()=>{
 assert.equal(riskText(undefined),'—');
 assert.equal(riskText(NaN),'—');
 assert.equal(riskText(0),'0');
 assert.equal(riskText(18.5),'18.5');
});
