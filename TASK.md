# Fix: replace remaining VibeDataService references

## What was already done
The rename from Vibe.Edge to KeelBase.Edge is staged in git (not yet committed).
The class VibeDataService was renamed to KeelBaseDataService in Data/KeelBaseDataService.cs,
but the files that USE it were not updated.

## Your job
1. In every .cs file under KeelBase.Edge/ that still contains the string VibeDataService,
   replace VibeDataService with KeelBaseDataService.
   The affected files are in: Admin/, Proxy/, Identity/, Authorization/, Authentication/, Health/, Credentials/
   Use grep or your read tool to find them. Do not guess — check first.

2. Run: dotnet build KeelBase.Edge/KeelBase.Edge.csproj -c Debug -nologo
   It must end with "0 Error(s)". If it does not, fix the errors and rebuild.

3. When the build is clean, run:
   git add -A
   git commit -m "pre-TS-02: rename Vibe.Edge -> KeelBase.Edge, swap Devart -> Npgsql"

4. Write REPORT.md in this directory (do not commit it):
   - List every file you changed
   - Last 5 lines of the build output
   - Build rc

Reply DONE when REPORT.md exists and the commit is made.
