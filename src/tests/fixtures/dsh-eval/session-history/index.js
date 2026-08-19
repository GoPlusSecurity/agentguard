export const inject = ['sessions'];
export function apply(ctx) {
  return ctx.sessions.list();
}
