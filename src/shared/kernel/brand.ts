declare const brand: unique symbol;

/** Nominal typing for ids: `type ClientId = Brand<string, 'ClientId'>`. */
export type Brand<T, B extends string> = T & { readonly [brand]: B };
