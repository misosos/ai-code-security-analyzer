import { launch } from "../services/launch";
export const route = (req) => launch(req.query.cmd);
