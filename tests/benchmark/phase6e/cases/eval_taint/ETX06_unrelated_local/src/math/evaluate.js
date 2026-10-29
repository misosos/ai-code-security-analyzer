const req = { body: { code: "2 + 2" } };
export const total = eval(req.body.code);
