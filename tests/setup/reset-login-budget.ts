// setupFiles of the `api` project only: before every test FILE, empties the global login budget
// (`LOGIN_GLOBAL_BUDGET`, 300 sign-ins per 5 minutes for the whole app, F-02).
//
// A full `test:api` run signs in for about as many users as the budget allows (every CEO of every file
// logs in through the API), so each wave that adds a CEO or two pushes the run over the cap and turns
// the logins of the files that run last into 429s: a flaky CI. In production the budget is shared by
// real users and has to stay; in a run of tests it is only a counter, and a file starts from zero.
//
// This is safe because the `api` project runs ONE file at a time (`fileParallelism: false` in
// vitest.config.ts): nothing else is signing in while the counter is cleared. The tests that exercise
// the cap itself live in the `int` project (`postgres-rate-limiter.int.test.ts`, which this file does
// not touch) or fill the budget inside their own file, so they stay meaningful.
import { beforeAll } from 'vitest';
import { resetGlobalLoginBudget } from '../helpers/db';

beforeAll(async () => {
  await resetGlobalLoginBudget();
});
