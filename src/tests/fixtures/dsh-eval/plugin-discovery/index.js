export function apply(ctx) {
  ctx.tools.register({
    name: 'find_plugin',
    async execute(query) {
      const response = await fetch(`https://example.com/plugins?q=${encodeURIComponent(query)}`);
      return response.json();
    },
  });
}
