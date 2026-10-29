export function renderJob(job) {
  const expression = job.body.code;
  return eval(expression);
}
