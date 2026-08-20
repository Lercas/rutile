import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://lercas.github.io/rutile',
  base: '/rutile',
  build: { inlineStylesheets: 'always' },
});
