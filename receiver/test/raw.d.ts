// Vite raw imports in tests (the README route-table check).
declare module "*.md?raw" {
  const text: string;
  export default text;
}
