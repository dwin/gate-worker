/** Vite `?raw` imports resolve to the file's text. */
declare module "*?raw" {
  const content: string;
  export default content;
}
