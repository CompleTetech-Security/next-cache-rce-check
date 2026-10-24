// Synthetic App Router context only. This is not a deployable application.
import { readArrays } from './data';
export default async function Page() {
  const arrays = await readArrays();
  return null;
}
