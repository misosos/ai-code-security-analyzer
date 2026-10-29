export function process(job) {
  return eval(job.body.code);
}
