```markdown
# Mainsky Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns, coding conventions, and workflows used in the Mainsky repository—a TypeScript project built with the Next.js framework. You'll learn how to structure files, write imports/exports, and follow the project's conventions for code and testing. This guide also provides suggested commands for common workflows.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `userProfile.ts`, `mainHeader.tsx`

### Import Style
- Use **alias imports** to reference modules.
  - Example:
    ```typescript
    import { UserService } from '@/services/userService';
    ```

### Export Style
- Both **named** and **default** exports are used.
  - Named export:
    ```typescript
    export function fetchData() { ... }
    ```
  - Default export:
    ```typescript
    export default App;
    ```

### Commit Patterns
- Commit messages are **freeform** (no enforced type or prefix).
- Average commit message length: **39 characters**.
  - Example:  
    ```
    Add user profile page and update routing
    ```

## Workflows

_No automated workflows detected in this repository._

## Testing Patterns

- **Test file pattern:** `*.test.*`
  - Example: `userService.test.ts`
- **Testing framework:** Not explicitly detected; check project dependencies for details.
- **Test Example:**
  ```typescript
  // userService.test.ts
  import { getUser } from '@/services/userService';

  test('should fetch user data', () => {
    const user = getUser(1);
    expect(user.id).toBe(1);
  });
  ```

## Commands

| Command      | Purpose                                 |
|--------------|-----------------------------------------|
| /test        | Run all test files (`*.test.*`)         |
| /lint        | Lint the codebase (if linter configured)|
| /dev         | Start the Next.js development server    |
| /build       | Build the Next.js project               |

```