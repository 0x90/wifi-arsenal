//  ====================================================================== 	//
//  BLAuthentication.h														//
//  																		//
//  Last Modified on Tuesday April 24 2001									//
//  Copyright 2001 Ben Lachman												//
//																			//
//	Thanks to Brian R. Hill <http://personalpages.tds.net/~brian_hill/>		//
//	Updated By Parovishnyk Vitalii aka Korich, 22.11.14						//
//  ====================================================================== 	//

#import "BLAuthentication.h"
#import <Security/AuthorizationTags.h>

@implementation BLAuthentication

// returns an instace of itself, creating one if needed
+ (id) sharedInstance
{
    static id sharedTask = nil;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        sharedTask = [[BLAuthentication alloc] init];
    });
    
    return sharedTask;
}

// initializes the super class and sets authorizationRef to NULL 
- (id)init
{
    if (self = [super init])
    {
        authorizationRef = NULL;
    }
    
    return self;
}

//============================================================================
//	- (BOOL)isAuthenticated:(NSArray *)forCommands
//============================================================================
// Find outs if the user has the appropriate authorization rights for the 
// commands listed in (NSArray *)forCommands.
// This should be called each time you need to know whether the user
// is authorized, since the AuthorizationRef can be invalidated elsewhere, or
// may expire after a short period of time.
//

static OSStatus su_AuthorizationExecuteWithPrivileges(AuthorizationRef authorization, const char *pathToTool, AuthorizationFlags flags, char *const *arguments)
{
	// flags are currently reserved
	if (flags != 0)
    {
		return errAuthorizationInvalidFlags;
    }
    
	char **(^argVector)(const char *, const char *, const char *, char *const *) = ^char **(const char *bTrampoline, const char *bPath,
																							const char *bMboxFdText, char *const *bArguments)
    {
		int length = 0;
		if (bArguments)
        {
            length = sizeof(bArguments);
		}
		
		const char **args = (const char **)malloc(sizeof(const char *) * (length + 4));
		if (args)
        {
			args[0] = bTrampoline;
			args[1] = bPath;
			args[2] = bMboxFdText;
			if (bArguments)
            {
				for (int n = 0; bArguments[n]; ++n)
                {
					args[n + 3] = bArguments[n];
                }
            }
			args[length + 3] = NULL;
			
            return (char **)args;
		}
        
		return NULL;
	};
	
	// externalize the authorization
	AuthorizationExternalForm extForm;
	OSStatus err;
	if ((err = AuthorizationMakeExternalForm(authorization, &extForm)))
    {
		return err;
    }
    
    // create the mailbox file
    FILE *mbox = tmpfile();
    if (!mbox)
    {
        return errAuthorizationInternal;
    }
    if (fwrite(&extForm, sizeof(extForm), 1, mbox) != 1)
    {
        fclose(mbox);
        return errAuthorizationInternal;
    }
    fflush(mbox);
    
    // make text representation of the temp-file descriptor
    char mboxFdText[20] = {0};
    snprintf(mboxFdText, sizeof(mboxFdText), "auth %d", fileno(mbox));
    
	// make a notifier pipe
    int notify[2] = {0};
	if (pipe(notify))
    {
        fclose(mbox);
		return errAuthorizationToolExecuteFailure;
    }
	
	// do the standard forking tango...
	int delay = 1;
	for (int n = 5;; n--, delay *= 2)
    {
		switch (fork())
        {
			case -1: { // error
				if (errno == EAGAIN)
                {
					// potentially recoverable resource shortage
					if (n > 0)
                    {
						sleep(delay);
						continue;
					}
				}
				close(notify[0]); close(notify[1]);
				return errAuthorizationToolExecuteFailure;
			}
            
            case 0:
            { // child
                // close foreign side of pipes
                close(notify[0]);
                
                // fd 1 (stdout) holds the notify write end
                dup2(notify[1], 1);
                close(notify[1]);
                
                // fd 0 (stdin) holds either the comm-link write-end or /dev/null
                close(0);
                open("/dev/null", O_RDWR);
                
                // where is the trampoline?
                const char *trampoline = "/usr/libexec/security_authtrampoline";
                char **argv = argVector(trampoline, pathToTool, mboxFdText, arguments);
                if (argv)
                {
                    execv(trampoline, argv);
                    free(argv);
                }
                
                // execute failed - tell the parent
                OSStatus error = errAuthorizationToolExecuteFailure;
                error = htonl(error);
                write(1, &error, sizeof(error));
                _exit(1);
            }
                
			default:
            {	// parent
				// close foreign side of pipes
				close(notify[1]);
                
				// close mailbox file (child has it open now)
				fclose(mbox);
				
				// get status notification from child
				OSStatus status;
				ssize_t rc = read(notify[0], &status, sizeof(status));
				status = ntohl(status);
				switch (rc)
                {
					default:				// weird result of read: post error
						status = errAuthorizationToolEnvironmentError;
						// fall through
					case sizeof(status):	// read succeeded: child reported an error
						close(notify[0]);
						return status;
					case 0:					// end of file: exec succeeded
						close(notify[0]);
						return noErr;
				}
			}
		}
	}
}

// Authorization code based on generous contribution from Allan Odgaard. Thanks, Allan!
static BOOL su_AuthorizationExecuteWithPrivilegesAndWait(AuthorizationRef authorization, const char* executablePath, AuthorizationFlags options, const char* const* arguments)
{
	// *** MUST BE SAFE TO CALL ON NON-MAIN THREAD!
	
	sig_t oldSigChildHandler = signal(SIGCHLD, SIG_DFL);
	BOOL returnValue = YES;
	
	if (su_AuthorizationExecuteWithPrivileges(authorization, executablePath, options, (char* const*)arguments) == errAuthorizationSuccess)
	{
		int status;
		pid_t pid = wait(&status);
		if (pid == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
			returnValue = NO;
        }
	}
	else
    {
		returnValue = NO;
    }
    
	signal(SIGCHLD, oldSigChildHandler);
    
	return returnValue;
}

//============================================================================
//	-(void)executeCommand:(NSString *)pathToCommand withArgs:(NSArray *)arguments
//============================================================================
// Executes command in (NSString *)pathToCommand with the arguments listed in
// (NSArray *)arguments as root.
// pathToCommand should be a string contain the path to the command 
// (eg., /usr/bin/more), arguments should be an array of strings each containing
// a single argument.
//
-(BOOL)executeCommand:(NSString *)pathToCommand withArgs:(NSArray *)arguments
{
	static OSStatus authStat = errAuthorizationDenied;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		while (authStat == errAuthorizationDenied)
        {
			authStat = AuthorizationCreate(NULL,
										   kAuthorizationEmptyEnvironment,
										   kAuthorizationFlagDefaults,
										   &authorizationRef);
		}
	});
	
	BOOL res = NO;
	if (authStat == errAuthorizationSuccess)
    {
		res = YES;
		const char** coParams = malloc(sizeof(char*) * [arguments count]);
		int i = 0;
		for (NSString *arg in arguments)
        {
			coParams[i++] = [arg UTF8String];
		}
		
		su_AuthorizationExecuteWithPrivilegesAndWait(authorizationRef, [pathToCommand UTF8String], kAuthorizationFlagDefaults, coParams);
        free(coParams);
	}
	
	return res;
}

@end
