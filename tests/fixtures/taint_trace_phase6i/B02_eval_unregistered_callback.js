function registerLike(app, handler) { handler({ query: { code: "" } }); }
registerLike(fakeApp, (req) => eval(req.query.code));
