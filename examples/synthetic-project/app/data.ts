// Synthetic return-shape fixture; contains no exploit payload.
export async function readArrays() {
  'use cache';
  return [new Uint8Array([1]), new Uint16Array([2])];
}
