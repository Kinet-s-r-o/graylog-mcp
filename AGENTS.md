### Code structure
    - Keep code modular and readable. Avoid large monolithic files; split functionality into focused modules by responsibility. 
    - Keep functions small and single-purpose. 
    - Prefer clear naming and structure over comments, and only comment non-obvious logic or important constraints.
    
## Context7
    Use Context7 for current documentation when working with external libraries, frameworks, SDKs, or APIs.

    - Prefer docs matching the version used by the project.
    - Check dependency/lock files for the installed version when relevant.
    - Do not rely on outdated model knowledge for library-specific APIs or configuration.
    - Do not invent undocumented methods, options, flags, or parameters.
    - Skip Context7 for standard language features and repository-local code.