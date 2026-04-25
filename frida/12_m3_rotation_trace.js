// M3.2 rotation crash tracer
// =========================
//
// Client B crashes immediately after its cube spawn when we write a
// rotation matrix to the cube's +0x30 slot then call UpdateDownwardPass.
// Client A doesn't crash — same code, same binary, same game state
// except for the remote-snapshot values (A receives B's pose; B receives
// A's pose, and A has been running longer with presumably different
// rotation values).
//
// This script hooks:
//   - sub_1416C8050 (UpdateDownwardPass, RVA 0x16C8050): dumps cube
//     state immediately before every call so we see what's being passed
//     when the crash fires.
//   - sub_1416BE170 (NiNode::AttachChild, RVA 0x16BE170): so we know
//     which calls are the spawn (first time) vs subsequent updates.
//   - Process-wide exception handler: when the game AVs, prints RIP,
//     registers, and a ~10-frame backtrace with symbols if possible.
//
// Attach this to Client B AFTER it's launched (or spawn it through
// Frida from spawn_m3_debug.py).

console.log('[m3-trace] script starting');

const game = Process.getModuleByName('Fallout4.exe');
console.log('[m3-trace] Fallout4.exe base: ' + game.base);

// -----------------------------------------------------------------------
// RVAs (from our ni_offsets.h + dossier)
// -----------------------------------------------------------------------
const RVA_UPDATE_DOWNWARD  = 0x16C8050;
const RVA_ATTACH_CHILD     = 0x16BE170;
const RVA_BSTRISHAPE_VT    = 0x267E948;  // confirm target is our cube

// BSGeometry layout (verified via our M2 dossier + M1 corrected offsets)
const OFF_REFCOUNT         = 0x08;
const OFF_LOCAL_ROTATE     = 0x30;   // NiMatrix3, 3×NiPoint4 (SIMD-padded 16B per row)
const OFF_LOCAL_TRANSLATE  = 0x60;   // vec3 + scale@+0x6C
const OFF_WORLD_ROTATE     = 0x70;
const OFF_WORLD_TRANSLATE  = 0xA0;
const OFF_FLAGS            = 0x108;
const OFF_ALPHA_PROP       = 0x130;
const OFF_SHADER_PROP      = 0x138;
const OFF_VDESC            = 0x150;

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------
function readMatrix3(ptrBase) {
    // 3 rows × 4 floats stride (3 meaningful + 1 pad per row)
    const rows = [];
    for (let r = 0; r < 3; r++) {
        const row = [];
        for (let c = 0; c < 3; c++) {
            row.push(ptrBase.add(r * 16 + c * 4).readFloat().toFixed(4));
        }
        rows.push('[' + row.join(', ') + ']');
    }
    return rows.join(' ');
}

function readVec3(p) {
    return '(' + p.readFloat().toFixed(1) + ', '
         + p.add(4).readFloat().toFixed(1) + ', '
         + p.add(8).readFloat().toFixed(1) + ')';
}

function safeVtRva(objPtr) {
    try {
        const vt = objPtr.readPointer();
        return '0x' + vt.sub(game.base).toString(16);
    } catch (e) { return '<read-fail>'; }
}

function isOurCube(nodePtr) {
    try {
        const vt = nodePtr.readPointer();
        return vt.sub(game.base).equals(ptr(RVA_BSTRISHAPE_VT));
    } catch (e) { return false; }
}

// -----------------------------------------------------------------------
// Hook UpdateDownwardPass
// -----------------------------------------------------------------------
const updateDownwardAddr = game.base.add(RVA_UPDATE_DOWNWARD);
console.log('[m3-trace] hooking UpdateDownwardPass @ ' + updateDownwardAddr);

Interceptor.attach(updateDownwardAddr, {
    onEnter: function (args) {
        const node = args[0];
        const updateData = args[1];
        this.isCube = isOurCube(node);
        if (!this.isCube) return;

        this.nodePtr = node;
        console.log('\n[UpdateDownward][CUBE] ==>  call #' + (++global_call_idx));
        console.log('  node=' + node + '  updateData=' + updateData);
        try {
            console.log('  refcount=' + node.add(OFF_REFCOUNT).readU32());
            console.log('  flags=0x' + node.add(OFF_FLAGS).readU64().toString(16));
            console.log('  local.rot ' + readMatrix3(node.add(OFF_LOCAL_ROTATE)));
            console.log('  local.trans=' + readVec3(node.add(OFF_LOCAL_TRANSLATE)));
            console.log('  local.scale=' + node.add(0x6C).readFloat().toFixed(3));
            console.log('  world.rot  ' + readMatrix3(node.add(OFF_WORLD_ROTATE)));
            console.log('  world.trans=' + readVec3(node.add(OFF_WORLD_TRANSLATE)));
            console.log('  alpha@+0x130=' + node.add(OFF_ALPHA_PROP).readPointer());
            console.log('  shader@+0x138=' + node.add(OFF_SHADER_PROP).readPointer());
            console.log('  vdesc@+0x150=0x' + node.add(OFF_VDESC).readU64().toString(16));
        } catch (e) {
            console.log('  [read failed: ' + e + ']');
        }
    },
    onLeave: function (retval) {
        if (!this.isCube) return;
        console.log('[UpdateDownward][CUBE] <== ret=' + retval);
    }
});

var global_call_idx = 0;

// -----------------------------------------------------------------------
// Hook AttachChild (so we know when cube is first spawned)
// -----------------------------------------------------------------------
const attachChildAddr = game.base.add(RVA_ATTACH_CHILD);
console.log('[m3-trace] hooking AttachChild @ ' + attachChildAddr);

Interceptor.attach(attachChildAddr, {
    onEnter: function (args) {
        const parent = args[0];
        const child = args[1];
        if (!isOurCube(child)) return;
        console.log('\n[AttachChild][CUBE] parent=' + parent
            + ' (vt_rva=' + safeVtRva(parent) + ')'
            + '  child=' + child
            + '  reuseFirstEmpty=' + args[2].toInt32());
    }
});

// -----------------------------------------------------------------------
// Process exception handler
// -----------------------------------------------------------------------
Process.setExceptionHandler(function (details) {
    console.log('\n\n========== EXCEPTION CAUGHT ==========');
    console.log('type: ' + details.type);
    console.log('address: ' + details.address
        + ' (RVA 0x' + details.address.sub(game.base).toString(16) + ')');
    if (details.memory) {
        console.log('memory op: ' + details.memory.operation
            + ' @ ' + details.memory.address);
    }
    if (details.context) {
        const c = details.context;
        console.log('registers:');
        console.log('  rip=' + c.rip + '  rsp=' + c.rsp);
        console.log('  rax=' + c.rax + '  rbx=' + c.rbx);
        console.log('  rcx=' + c.rcx + '  rdx=' + c.rdx);
        console.log('  r8 =' + c.r8  + '  r9 =' + c.r9);
        console.log('  r10=' + c.r10 + '  r11=' + c.r11);
    }
    try {
        const frames = Thread.backtrace(details.context, Backtracer.ACCURATE);
        console.log('backtrace:');
        frames.slice(0, 15).forEach(function (f, i) {
            const rva = '0x' + f.sub(game.base).toString(16);
            const sym = DebugSymbol.fromAddress(f).toString();
            console.log('  #' + i + '  ' + f + ' (RVA ' + rva + ') ' + sym);
        });
    } catch (e) {
        console.log('backtrace error: ' + e);
    }
    console.log('=======================================\n');
    return false; // let OS crash — we just want the info
});

console.log('[m3-trace] all hooks armed, ready for Client B to crash');
