export function TextOutput({ value }: { value: string }) {
  return <output>{String(value)}</output>;
}
