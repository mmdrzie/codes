// Declaration merging برای Zod
declare module 'zod' {
  export const z: {
    object: typeof import('zod').object;
    string: typeof import('zod').string;
    number: typeof import('zod').number;
    boolean: typeof import('zod').boolean;
    array: typeof import('zod').array;
    // ... سایر متدها
  };
  
  export default z;
}