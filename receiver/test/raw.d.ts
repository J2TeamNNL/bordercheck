// Vite's ?raw imports in tests: the file's text, read when the test is built
// (the README route-table check, the Go message catalogue).
declare module "*?raw" {
  const text: string;
  export default text;
}
