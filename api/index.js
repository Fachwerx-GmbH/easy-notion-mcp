// Vercel entry point. Every route is rewritten here; dist/ is built by `npm run build`.
import { createAppFromEnv } from "../dist/http.js";

export default await createAppFromEnv();
