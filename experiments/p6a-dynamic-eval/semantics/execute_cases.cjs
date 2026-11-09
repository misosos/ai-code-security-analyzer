// P6-A-R: execute every synthetic case file and compare the observed behaviour with its label.
//
// Safety: each case is our own synthetic file, run in a fresh `vm` context with no host objects.
// The only code ever evaluated is the fixed probe string below; no input is read from anywhere.
//
// Probe: "typeof arguments".
//   "object"     -> direct eval (it sees the calling function's `arguments`)
//   "undefined"  -> indirect eval (global scope only; `arguments` is not declared there)
//   other value / SyntaxError from JSON.parse / TDZ ReferenceError -> no code evaluation
// Browser cases are simulated with `var window = globalThis` (window === globalThis in browsers);
// see browser_window_cases.cjs for the real-browser check.
//
//   node experiments/p6a-dynamic-eval/semantics/execute_cases.cjs
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const labels = JSON.parse(fs.readFileSync(path.join(root, 'labels.json'), 'utf8'));
const PROBE = 'typeof arguments';
const IDENTITY = '(v) => v';

// Scenarios per case: [scenario name, call expression evaluated in the case context].
const P = [['default', 'run(PROBE)']];
const scenarios = {
  N01_const_json_parse: [['default', 'parse(PROBE)']],
  N02_let_json_parse: [['default', 'parse(PROBE)']],
  N03_const_local_function: [['default', 'echo(PROBE)']],
  N05_method_named_eval: [['policy object', `check({ eval: ${IDENTITY} }, PROBE)`]],
  N06_inner_shadow_under_a8: P,
  N07_local_window_object: [['default', 'run(PROBE)']],
  N08_let_reassigned_after_builtin: [['default', 'parse(PROBE)']],
  U01_parameter_named_eval: [['caller passes %eval%', 'run(globalThis.eval, PROBE)'], ['caller passes JSON.parse', 'run(JSON.parse, PROBE)']],
  U02_unknown_factory: [['factory returns %eval%', 'globalThis.getEvaluator = () => globalThis.eval; run(PROBE)'],
                        ['factory returns identity', `globalThis.getEvaluator = () => ${IDENTITY}; run(PROBE)`]],
  U03_conditional_builtin: [['useNative=true', 'run(PROBE, true)'], ['useNative=false', 'run(PROBE, false)']],
  U04_configured_evaluator: [['config holds %eval%', 'run(PROBE, { evaluator: globalThis.eval })'],
                             ['config holds identity', `run(PROBE, { evaluator: ${IDENTITY} })`]],
};

function classify(run) {
  try {
    const value = run();
    if (value === 'object') return 'direct-eval';
    if (value === 'undefined') return 'indirect-eval';
    return `no-eval (returned ${JSON.stringify(value)})`;
  } catch (error) {
    const name = error && error.constructor ? error.constructor.name : 'Error';
    return `no-eval (${name}: ${error.message})`;
  }
}

function execute(site, expression) {
  const source = fs.readFileSync(path.join(root, site.file), 'utf8');
  const context = vm.createContext({});
  vm.runInContext('var window = globalThis;', context);
  try {
    vm.runInContext(source, context, { filename: site.file });
  } catch (error) {
    return `load-error (${error.constructor.name}: ${error.message})`;
  }
  context.PROBE = PROBE;
  return classify(() => vm.runInContext(expression, context));
}

let disagreements = 0;
const lines = [`# node ${process.version} — node experiments/p6a-dynamic-eval/semantics/execute_cases.cjs`, `# probe: ${JSON.stringify(PROBE)}`];
for (const site of labels.sites) {
  const results = (scenarios[site.case] ?? P).map(([name, expression]) => [name, execute(site, expression)]);
  const evaluated = results.map(([, outcome]) => outcome.endsWith('eval') && !outcome.startsWith('no-eval'));
  let observed;
  if (results.some(([, outcome]) => outcome.startsWith('load-error (SyntaxError'))) observed = 'invalid_program';
  else if (results.length > 1 && new Set(evaluated).size > 1) observed = 'undetermined';
  else if (evaluated.every(Boolean)) observed = 'positive';
  else if (evaluated.every((value) => !value)) observed = 'negative';
  else observed = 'inconsistent';
  const agrees = observed === site.label;
  if (!agrees) disagreements += 1;
  lines.push(`${site.case.padEnd(36)} label=${site.label.padEnd(15)} observed=${observed.padEnd(15)} ${agrees ? 'OK' : 'DISAGREE'}`);
  for (const [name, outcome] of results) lines.push(`    ${name}: ${outcome}`);
}
lines.push(`# sites=${labels.sites.length} disagreements=${disagreements}`);

// Strict code rejects every binding named `eval` at parse time (compiled only, never run).
const strictForms = [
  'const eval = globalThis.eval;', 'let eval = globalThis.eval;', 'var eval = globalThis.eval;',
  'const { eval } = globalThis;', 'function f(eval) { return eval; }', '(eval) => eval;',
];
lines.push('# strict-mode compile check (vm.Script, not executed)');
for (const form of strictForms) {
  let outcome = 'compiles';
  try { new vm.Script(`'use strict'; function g() { ${form} }`); } catch (error) { outcome = `${error.constructor.name}: ${error.message}`; }
  lines.push(`    ${form.padEnd(36)} ${outcome}`);
}
console.log(lines.join('\n'));
process.exitCode = disagreements === 0 ? 0 : 1;
