---
applyTo: '**'
---
Provide project context and coding guidelines that AI should follow when generating code, answering questions, or reviewing changes.
# ULTIMATE AGENT LOADER: MAG-SP00F PROJECT (EFFICIENCY-OPTIMIZED)

---

## PROJECT IDENTITY
- **Name:** EMVPort
- **Package:** com.nf-sp00f.app.emv
- **Purpose:** Port the Proxmark3 Iceman Forks EMV Engine to Kotlin for Android Use.
- **Memory System:** Remember MCP for persistent context and rules and utilize a local json based memory.

---

## CRITICAL ANTI-PATTERN RULES (AGENT VIOLATION PREVENTION)

### 🚨 FILE CORRUPTION PREVENTION
- **NEVER append or atomic edit files** - After the first time the file is created thats it, the only options you have is to use the PatchPilot VSCode extention (Ill have a section below on it, or Delete entire file →                        Regenerate from scratch with ALL requirements → Verify syntax → Write clean production code, use terminal text editor approach)
- **NO duplicate imports throughout file** - Single import block at top only
- **NO repeated code blocks** - One function/class per file, no duplicates
- **NO case-sensitive naming errors** - Enforce snake_case (Python), PascalCase (Java/Kotlin)
- **NO functions outside scope** - All functions properly contained within classes/modules
- **NO leftover legacy code** - Clean slate rewrites when corruption detected

### 🔧 FILE REGENERATION PROTOCOL
When files show ANY of these symptoms:
- Multiple import blocks
- Duplicate functions/classes
- Code appended after main logic
- Mixed naming conventions
- Syntax errors from patching

**IMMEDIATE ACTION:** Delete entire file → Regenerate from scratch with ALL requirements → Verify syntax → Write clean production code, use terminal text editor approach

### 🔧 CRITICAL: USE PATCHPILOT VSCODE EXTENSION API FOR ALL FILE EDITS
**MANDATORY:** ALL FILE EDITS MUST USE PATCHPILOT API TO PREVENT CORRUPTION
ONLY EXCEPTION: First-time file creation OR majorly corrupted files (follow regeneration protocol)

**PATCHPILOT API INTEGRATION:**
```typescript
// Apply patch with preview (RECOMMENDED)
const results = await vscode.commands.executeCommand('patchPilot.applyPatch', patchText, { 
    preview: true,
    createBackup: true 
});

// Parse patch without applying (validation)
const fileInfo = await vscode.commands.executeCommand('patchPilot.parsePatch', patchText);

// Create Git branch for changes
const branchName = await vscode.commands.executeCommand('patchPilot.createBranch', 'emv-port-changes');

// Batch apply multiple patches
const batchResults = await vscode.commands.executeCommand('patchPilot.applyMultiplePatches', [
    { patch: patch1, options: { preview: true } },
    { patch: patch2, options: { preview: true } }
]);
```

**AGENT INSTRUCTIONS FOR PATCHPILOT:**
**CONTEXT:** I am using VS Code PatchPilot extension. Your primary task when I request code changes is to provide ONLY the modifications in **unified diff format**. Do NOT output complete modified files.

**MANDATORY DIFF FORMAT RULES:**
1.  **OUTPUT FORMAT:** MUST be **unified diff** with proper headers
    ```diff
    diff --git a/path/to/file.ext b/path/to/file.ext
    --- a/path/to/file.ext
    +++ b/path/to/file.ext
    @@ -old_start,old_lines +new_start,new_lines @@
     context line (unchanged)
    -line to remove
    +line to add
     another context line
    ```

2.  **FILE PATHS:** MUST use correct **relative paths** from project root in all headers
    - ✅ Correct: `Android EMV/src/main/kotlin/com/nf_sp00f/app/emv/EmvEngine.kt`
    - ❌ Wrong: `EmvEngine.kt` or `/absolute/path/to/EmvEngine.kt`

3.  **CONTEXT LINES:** MUST include **at least 3 lines** of unchanged context before and after changes
    - Lines starting with space (` `) are context lines
    - Essential for PatchPilot to locate exact change locations

4.  **MULTI-FILE CHANGES:** Combine into **single diff block** with separate headers per file
5.  **NEW FILES:** Use `/dev/null` as source in headers
6.  **AUTOMATIC NORMALIZATION:** PatchPilot handles line endings and leading spaces

**PATCHPILOT WORKFLOW:**
1. Generate unified diff format
2. Call `patchPilot.applyPatch` with `preview: true`
3. User reviews changes in PatchPilot UI
4. Apply if approved, reject if issues found
5. Automatic backup creation for safety

**CORRUPTION PREVENTION:** PatchPilot eliminates:
- Multiple import blocks
- Duplicate functions/classes  
- Code appended after main logic
- Mixed naming conventions
- Syntax errors from manual patching

***END OF PATCHPILOT INFO

### 📋 LARGE FILE HANDLING
For files exceeding agent view window:
1. Split into logical sections for review
2. Read each section completely before editing
3. Regenerate entire file maintaining all sections
4. Verify complete file integrity post-generation

---

## PHASE 0: ENVIRONMENT & STARTUP OPTIMIZATION

### Development Environment Paths
- **JAVA_HOME:** `/opt/openjdk-bin-17`
- **ANDROID_SDK_ROOT:** `/home/user/Android/Sdk`
- **NDK_PATH:** `/home/user/Android/Sdk/ndk/[version]`
- **GRADLE_OPTS:** Configure for Android builds with proper JDK

### Memory System Initialization
- Load Remember MCP for persistent project context
- Retrieve stored rules, preferences, and project state
- Auto-detect VSCode extensions and workspace configuration
- Initialize efficiency tracking metrics
- Create a local based memory also in json format in the /docs/mem/ (create if it dont exist)

### VSCode Automation Setup
- `/.vscode/tasks.json` - Build, run, debug, agent script execution
- `/.vscode/launch.json` - Debug configurations for Android and scripts
- **PatchPilot Integration:** Configure tasks to use PatchPilot API for file modifications
- Validate automation files after every major update
- Include automation status in all environment checks

---


### Script Quality Standards
- **Top-level docstring:** Clear purpose and usage
- **Function docstrings:** Parameters, returns, exceptions
- **Section comments:** Explain logic flow and decisions
- **Error handling:** Graceful failures with user-friendly messages
- **Efficiency focus:** Minimize redundant operations
- **Remember MCP integration:** Store script status and results

---

## PHASE 3: BATCHED EXECUTION WITH EFFICIENCY METRICS

### Batch Processing Protocol
1. **Load batch from batches.yaml** (max 4-5 atomic tasks)
2. **Pre-batch validation:** Check for file corruption indicators
3. **Execute tasks sequentially** with corruption monitoring
4. **Post-batch audit:** Run all validation scripts
5. **Efficiency tracking:** Log time, operations, success rate
6. **Memory sync:** Update Remember MCP with progress and learnings

### Quality Gates
- Zero tolerance for file appending/patching
- Mandatory syntax validation before file writes
- Naming convention enforcement
- Production-grade code standards
- Performance optimization checks

### Error Recovery
- **File corruption detected:** Immediate regeneration protocol
- **Build failures:** Auto-backup restoration available
- **Naming violations:** Automatic correction with user notification
- **Syntax errors:** Full file regeneration with enhanced validation

### Remember MCP Integration
- Store project preferences and coding standards
- Maintain agent performance metrics
- Preserve successful code patterns
- Track common error patterns for prevention

---

## PHASE 5: QUALITY ENFORCEMENT (ZERO-TOLERANCE)

### Naming Convention Enforcement
- **Python files:** snake_case
- **Java/Kotlin files:** PascalCase for classes, camelCase for methods
- **Package names:** com.mag-sp00f.app
- **Resource files:** lowercase with underscores

### Code Quality Standards
- No placeholders, stubs, or TODO comments
- No demo/sample data in production code
- All functions properly scoped and contained
- Single responsibility principle enforced
- Error handling comprehensive and user-friendly

### Security & Privacy
- No user data exposure in logs or agent scripts
- No arbitrary shell command execution without review
- Agent scripts never included in shipped application
- All sensitive operations logged and auditable

---

## PHASE 6: EFFICIENCY OPTIMIZATION & REPORTING

### Performance Metrics
- Batch completion time tracking
- File regeneration frequency (target: minimize)
- Audit success rate (target: 100%)
- Code quality score progression
- User satisfaction with output quality

### Handoff Reporting
```
Current Status:
├── Active Batch: [ID and description]
├── Completion Rate: [percentage]
├── Outstanding Issues: [NEEDS INPUT items]
├── Quality Score: [current metrics]
├── Next Recommended Actions: [prioritized list]
└── Remember MCP Sync Status: [timestamp]
```

### Release Preparation
- Execute export_for_release.py
- Validate all agent scripts removed from build
- Generate final quality checklist
- Verify naming convention compliance
- Confirm no file corruption exists

---

## CONTINUOUS IMPROVEMENT PROTOCOL

### Agent Learning Integration
- Log successful patterns to Remember MCP
- Document recurring issues and solutions
- Update rules based on user feedback
- Optimize batch sizing for maximum efficiency
- Refine corruption detection algorithms

### Documentation Maintenance
- Auto-update instructions.md with new rules
- Enhance prompts.md with learned patterns
- Maintain CHANGELOG.md with detailed action log
- Sync all documentation with Remember MCP

---

## EMERGENCY PROCEDURES

### File Corruption Recovery
1. **Detect:** Multiple imports, duplicate functions, syntax errors
2. **Backup:** Auto-save current state if salvageable
3. **Regenerate:** Delete corrupted file completely
4. **Rebuild:** Create from scratch with all requirements
5. **Validate:** Comprehensive syntax and quality check
6. **Document:** Log incident and prevention measures

### Performance Degradation Response
1. **Identify:** Batch completion time increasing
2. **Analyze:** Review recent changes and patterns
3. **Optimize:** Adjust batch sizing and validation frequency
4. **Monitor:** Track improvement metrics
5. **Learn:** Update Remember MCP with optimization insights

---

## SUCCESS METRICS

- **Zero file corruption incidents per project**
- **100% naming convention compliance**
- **Sub-2-minute average batch completion time**
- **95%+ first-pass audit success rate**
- **Comprehensive Remember MCP integration**
- **Production-ready code quality throughout**

---

*This LOADER.md is optimized for maximum efficiency while maintaining zero tolerance for the common agent failures that waste user time. All operations focus on getting clean, working results quickly while building institutional memory for continuous improvement.*
