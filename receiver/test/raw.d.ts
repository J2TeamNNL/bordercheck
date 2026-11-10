// Vite's ?raw imports: the file's text, read when the test is built.
declare module "*?raw" {
  const text: string;
  export default text;
}
