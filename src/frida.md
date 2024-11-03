# Frida Dynamic Instrumentation Cheatsheet

## Installation
```bash
# Install Frida
pip install frida-tools frida

# Install Frida CLI tools
npm install -g frida-compile
npm install -g frida-create

# Android Setup
# Download frida-server from GitHub releases
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

## Basic Commands
### Process Management
```bash
# List processes
frida-ps -U  # USB devices
frida-ps -R  # Remote devices
frida-ps     # Local processes

# Attach to process
frida -U ProcessName
frida -U -p 1234
```

## JavaScript API
### Basic Hooking
```javascript
// Hook function
Interceptor.attach(targetAddr, {
    onEnter: function(args) {
        console.log('Function called');
        console.log('Arg1:', args[0]);
    },
    onLeave: function(retval) {
        console.log('Return value:', retval);
    }
});

// Replace function
Interceptor.replace(targetAddr, new NativeCallback(function () {
    console.log('Function replaced');
    return 0;
}, 'int', []));
```

### Memory Operations
```javascript
// Read/Write memory
Memory.readByteArray(ptr, size)
Memory.writeByteArray(ptr, array)
Memory.readCString(ptr)
Memory.readUtf8String(ptr)
Memory.protect(ptr, size, protection)

// Allocate memory
Memory.alloc(size)
Memory.allocUtf8String(str)
```

## Module & Function Manipulation
### Module Operations
```javascript
// Find module
Module.load('library.so')
Module.findBaseAddress('library.so')
Module.enumerateImports('library.so')
Module.enumerateExports('library.so')

// Find patterns
Memory.scan(addr, size, pattern, callbacks)
```

### Function Instrumentation
```javascript
// Hook exported function
Interceptor.attach(Module.getExportByName(null, 'open'), {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        console.log('open(' + this.path + ') => ' + retval);
    }
});
```

## Java/Android Instrumentation
### Java Methods
```javascript
// Hook Java method
Java.perform(() => {
    const Activity = Java.use('android.app.Activity');
    Activity.onCreate.implementation = function() {
        console.log('onCreate called');
        this.onCreate.call(this);
    };
});

// Call Java method
Java.choose('com.example.Class', {
    onMatch: function(instance) {
        console.log('Found instance');
    },
    onComplete: function() {}
});
```

### Android Specific
```javascript
// Hook constructor
Java.use('com.example.Class').$init.implementation = function() {
    console.log('Constructor called');
    this.$init();
};

// Android logging
console.log('Logging to logcat');
send('Logging to Frida client');
```

## iOS Instrumentation
### Objective-C
```javascript
// Hook Objective-C method
Interceptor.attach(ObjC.classes.NSString['- length'].implementation, {
    onEnter: function(args) {
        const obj = new ObjC.Object(args[0]);
        console.log('NSString length:', obj.toString());
    }
});

// Modify return value
ObjC.classes.UIDevice.currentDevice().isJailbroken.implementation = function() {
    return 0;
};
```

## Advanced Features
### RPC Exports
```javascript
// Server side
rpc.exports = {
    add: function(a, b) {
        return a + b;
    }
};

// Client side
script.exports.add(2, 3).then(console.log);
```

### Stalker (Instruction Tracing)
```javascript
// Trace instructions
Stalker.follow(threadId, {
    events: {
        call: true,
        ret: true
    },
    onReceive: function(events) {
        console.log('Events:', events);
    }
});
```

## Scripts & Automation
### Script Template
```javascript
// frida-script.js
Java.perform(() => {
    console.log('Script loaded');
    
    // Your hooks here
    
    console.log('Script completed');
});
```

### Running Scripts
```bash
# Run script
frida -U -l script.js ProcessName
frida -U -l script.js -f com.example.app --no-pause

# Compile TypeScript
frida-compile script.ts -o script.js
```

## Common Tasks
### SSL Pinning Bypass
```javascript
// Android
Java.perform(() => {
    const TrustManager = Java.registerClass({
        name: 'custom.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function() {},
            checkServerTrusted: function() {},
            getAcceptedIssuers: function() { return []; }
        }
    });
});

// iOS
Interceptor.replace(
    ObjC.classes.AFSecurityPolicy['- setSSLPinningMode:'].implementation,
    new NativeCallback(() => {}, 'void', ['pointer', 'int'])
);
```

### Anti-Debug Bypass
```javascript
// Patch isDebuggerAttached
Interceptor.replace(Module.getExportByName(null, 'isDebuggerAttached'), 
    new NativeCallback(() => {
        return 0;
    }, 'int', [])
);
```

## Tips & Best Practices
### Performance
1. Minimize Hook Scope
```javascript
// Bad
Interceptor.attach(ptr, { onEnter: () => { /* ... */ }});

// Good
if (shouldHook) {
    Interceptor.attach(ptr, { onEnter: () => { /* ... */ }});
}
```

2. Memory Management
```javascript
// Clean up resources
script.unload();
Stalker.unfollow();
Process.setExceptionHandler(null);
```

### Debugging
1. Error Handling
```javascript
try {
    // Your code
} catch(e) {
    console.error(e.stack);
}
```

2. Logging
```javascript
// Different log levels
console.log('Info message');
console.warn('Warning message');
console.error('Error message');
```

3. Process Events
```javascript
Process.setExceptionHandler((ex) => {
    console.log('Exception:', ex);
    return false;
});
```
