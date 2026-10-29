const decoder = { eval(value) { return value.trim(); } };
export const result = decoder.eval("abc");
