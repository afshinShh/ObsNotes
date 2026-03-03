### Framework‑specific Gotchas

| Framework      | Dangerous APIs / patterns                                                                    | Latest CVE/Issues                                                   |
| -------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| **React 19**   | `dangerouslySetInnerHTML`, `use()` hook with unsanitized data, concurrent rendering races    | Hydration mismatch bugs, `useFormStatus` edge cases                 |
| **Vue 3.4+**   | `v-html`, dynamic component names (`:<is="...">`)`, `v-html` with Composition API refs       | Server-side rendering XSS in `renderToString`                       |
| **Svelte 5**   | `{@html ...}`, runes (`$state`, `$derived`) with HTML content, event directives              | Fine-grained reactivity can bypass sanitization                     |
| **Next.js 15** | `next/script strategy="beforeInteractive"`, Server Actions with unvalidated input, edge gaps | Turbopack dev server XSS (CVE-2024-XXXXX), RSC serialization issues |
| **Solid 2.0**  | `innerHTML` in reactive statements, `<Dynamic>` component with user props                    | Signal-based XSS when reactivity wraps unsafe HTML                  |
| **Astro 4.x**  | `set:html` in `.astro` components, framework islands with unescaped props                    | Server-side XSS in content collections                              |
| **Qwik**       | `dangerouslySetInnerHTML` equivalent, resumability serialization issues                      | Hydration boundary XSS                                              |
| **Remix 2.x**  | Loader data XSS, `<Scripts/>` with inline data, Form action injection                        | Deferred loader data without sanitization                           |
| **Angular 17** | `bypassSecurityTrust*` methods, `[innerHTML]` binding, custom element XSS                    | SSR hydration mismatch, signal-based XSS                            |

### Framework‑specific Gotchas

| Framework      | Dangerous APIs / patterns                                                                    | Latest CVE/Issues                                                   |
| -------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| **React 19**   | `dangerouslySetInnerHTML`, `use()` hook with unsanitized data, concurrent rendering races    | Hydration mismatch bugs, `useFormStatus` edge cases                 |
| **Vue 3.4+**   | `v-html`, dynamic component names (`:<is="...">`)`, `v-html` with Composition API refs       | Server-side rendering XSS in `renderToString`                       |
| **Svelte 5**   | `{@html ...}`, runes (`$state`, `$derived`) with HTML content, event directives              | Fine-grained reactivity can bypass sanitization                     |
| **Next.js 15** | `next/script strategy="beforeInteractive"`, Server Actions with unvalidated input, edge gaps | Turbopack dev server XSS (CVE-2024-XXXXX), RSC serialization issues |
| **Solid 2.0**  | `innerHTML` in reactive statements, `<Dynamic>` component with user props                    | Signal-based XSS when reactivity wraps unsafe HTML                  |
| **Astro 4.x**  | `set:html` in `.astro` components, framework islands with unescaped props                    | Server-side XSS in content collections                              |
| **Qwik**       | `dangerouslySetInnerHTML` equivalent, resumability serialization issues                      | Hydration boundary XSS                                              |
| **Remix 2.x**  | Loader data XSS, `<Scripts/>` with inline data, Form action injection                        | Deferred loader data without sanitization                           |
| **Angular 17** | `bypassSecurityTrust*` methods, `[innerHTML]` binding, custom element XSS                    | SSR hydration mismatch, signal-based XSS                            |