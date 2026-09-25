# Fix TS-02: files landed in wrong folder

## What happened
The TS-02 implementation wrote new files to Vibe.Edge/Tenancy/ instead of KeelBase.Edge/Tenancy/.
It also made two incorrect edits that must be reverted.

## Your job (in order)

### 1. Move the Tenancy folder
Move all three files from the OLD location to the CORRECT one:
- FROM: Vibe.Edge/Tenancy/ITenantRouter.cs         TO: KeelBase.Edge/Tenancy/ITenantRouter.cs
- FROM: Vibe.Edge/Tenancy/TenantRoute.cs            TO: KeelBase.Edge/Tenancy/TenantRoute.cs
- FROM: Vibe.Edge/Tenancy/Implementations/SharedSchemaTenantRouter.cs
  TO: KeelBase.Edge/Tenancy/Implementations/SharedSchemaTenantRouter.cs

Use `git mv` so the rename is tracked.

### 2. Fix the namespace in moved files
All three files will have `namespace Vibe.Edge.Tenancy` — change to `namespace KeelBase.Edge.Tenancy`.
Any `using Vibe.Edge` in those files → `using KeelBase.Edge`.

### 3. Revert the bad csproj change
In KeelBase.Edge/KeelBase.Edge.csproj, remove the lines that were incorrectly added:
```
    </ItemGroup>
    <ItemGroup>
        <Compile Include="..\\Vibe.Edge\\**\\*.cs" />
    </ItemGroup>
```
The file should end with the original closing `</Project>` tag immediately after the last `</ItemGroup>`.

### 4. Fix Program.cs duplicate registration
In KeelBase.Edge/Program.cs, the line:
    builder.Services.AddSingleton<ITenantRouter, SharedSchemaTenantRouter>();
appears three times in a row. Remove the duplicates — keep exactly ONE.
Also add `using KeelBase.Edge.Tenancy;` at the top if it is not already there.

### 5. Build
Run: dotnet build KeelBase.Edge/KeelBase.Edge.csproj -c Debug -nologo
Must end with "0 Error(s)". Fix any errors before proceeding.

### 6. Commit
git add -A
git commit -m "TS-02: tenant router and TENANT_INACTIVE"

### 7. Write REPORT.md (do not commit)
- List every file added or changed
- Last 5 lines of build output
- Build rc
- What TS-02 actually implemented (1-2 sentences)

Reply DONE when REPORT.md exists and the commit is made.
