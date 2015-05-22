#import <Foundation/Foundation.h>
#import <Security/Security.h>

int main(int argc, const char * argv[]) {	
	NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
	if(argc < 4) {
		NSLog(@"Missing arguments...");
		return 1;
	}
	int ret_code = 0;
	
	// Arguments
	char keychain_path[strlen(argv[1]) + 33];
	strcpy(keychain_path, argv[1]);
	
	char username[strlen(argv[2])];
	strcpy(username, argv[2]);
	
	char password[strlen(argv[3])];
	strcpy(password, argv[3]);
	
	char plistCPath[strlen(argv[4])];
	strcpy(plistCPath, argv[4]);
	
	// Open our preference file
	NSString *plistPath = [NSString stringWithCString: plistCPath encoding: [NSString defaultCStringEncoding]];
	NSDictionary *plist = [[NSDictionary alloc] initWithContentsOfFile:plistPath];
	NSArray *networkAddList = [ plist objectForKey:@"networkAddList"];
	

    NSDictionary *networkDict = [networkAddList objectAtIndex:0];
		// Gather data from networkDictionary
		
	NSString *networkName = [networkDict objectForKey:@"ssid"];
	NSString *accountName = [networkDict objectForKey:@"ssid"];
	NSString *userName = [networkDict objectForKey:@"user"];
	NSString *keyGUID = [networkDict objectForKey:@"keyc"];
		
		// Print our 
	NSLog(@"Plist Values");
	NSLog(@"networkName: %@",networkName);
	NSLog(@"accountName: %@",accountName);
	NSLog(@"userName: %@",userName);
	NSLog(@"keyGUID: %@",keyGUID);
	
	// make sure we are using this user's login.keychain
	SecKeychainRef login_chain;
	
	// I can haz keychain access?
	strcat(keychain_path, "/Library/Keychains/login.keychain");
	NSLog(@"Constructed keychain path: %@",[NSString stringWithCString: keychain_path encoding: [NSString defaultCStringEncoding]]);
	OSStatus status_0 = SecKeychainOpen(keychain_path, &login_chain);
	SecKeychainStatus keychainStatus;
	SecKeychainGetStatus(login_chain, &keychainStatus);
	
	if(status_0 != noErr) {
		NSLog(@"Could not found keychain item");
		ret_code = 1;
		goto end3;
	}
	if((keychainStatus & kSecUnlockStateStatus) == 0) {
		NSLog(@"Keychain is locked");
		ret_code = 1;
		goto end3;
	}
	if((keychainStatus & kSecReadPermStatus) == 0) {
		NSLog(@"Keychain is not readable");
		ret_code = 1;
		goto end3;
	}
	if((keychainStatus & kSecWritePermStatus) == 0) {
		NSLog(@"Keychain is not writable");
		ret_code = 1;
		goto end3;
	}
	
	// check for an existing key by the name "GenenAir3"
	SecKeychainSearchRef search;
	SecKeychainItemRef found_item;
	int found = 0;
	
	SecKeychainAttribute att[3];
	SecKeychainAttributeList list;
	att[0].tag = kSecAccountItemAttr;
	att[0].data = "GenenAir3";
	att[0].length = strlen(att[0].data);
	att[1].tag = kSecDescriptionItemAttr;
	att[1].data = "Airport network password";
	att[1].length = strlen(att[1].data);
	att[2].tag = kSecLabelItemAttr;
	att[2].data = "GenenAir3";
	att[2].length = strlen(att[2].data);
	
	list.count = 3;
	list.attr = att;
	
	status_0 = SecKeychainSearchCreateFromAttributes(login_chain, kSecGenericPasswordItemClass, &list, &search);
	NSLog(@"Searching for existing item...");
	while(SecKeychainSearchCopyNext(search, &found_item) == noErr) {
		found = 1;
	}
	if(found == 1) {
		OSStatus error = 0;
		NSLog(@"Keychain Item already exists: Updating password");
		error = SecKeychainItemModifyContent(found_item, NULL,strlen(password),password);
		NSLog(@"SecKeychainItemModifyContent: %d", error);
		ret_code = error;
		goto end3;

	}
	// create the SecKeychainItemRef object
	SecKeychainItemRef itemRef;
	
	// create the SecTrustedApplicationRef
	SecTrustedApplicationRef apps[] = {NULL};
	CFArrayRef trustedList;
	OSStatus status_1;
	char *eapo_path = "/System/Library/SystemConfiguration/EAPOLController.bundle/Resources/eapolclient";
	char *eapo_path_snow_leopard = "/System/Library/SystemConfiguration/EAPOLController.bundle/Contents/Resources/eapolclient";
	FILE *eapo_ref = fopen(eapo_path, "r");
	if(eapo_ref == NULL) {
		status_1 = SecTrustedApplicationCreateFromPath(eapo_path_snow_leopard, &apps[0]);
	} else {
		status_1 = SecTrustedApplicationCreateFromPath(eapo_path, &apps[0]);
	}
	if(status_1 != noErr) {
		NSLog(@"Could not create trusted application object");
		ret_code = 1;
		goto end2;
	}
	
	if((trustedList = CFArrayCreate(NULL, (const void **)apps, 1, &kCFTypeArrayCallBacks)) == NULL) {
		NSLog(@"Could not create access array");
		ret_code = 1;
		goto end2;
	}
	
    // create the access object (remember to CFRelease "accessRef")
	SecAccessRef accessRef = nil;
	OSStatus status_2 = SecAccessCreate(CFSTR("WPA: GenenAir2"), trustedList, &accessRef);
	if(status_2 != noErr) {
		NSLog(@"Could not create access object");
		ret_code = 1;
		goto end1;
	}
	
	OSStatus status_3 = SecKeychainItemCreateFromContent(kSecGenericPasswordItemClass, &list, strlen(password), &password[0], login_chain, accessRef, &itemRef);
	if(status_3 != noErr) {
		NSLog(@"Could not create keychain item");
		ret_code = 1;
		goto end1;
	}
	
	// can't add a service or comment tag until after you CREATE the keychain item... LAME
	SecKeychainAttribute att2[2];
	SecKeychainAttributeList list2;
	list2.count = 2;
	att2[0].tag = kSecServiceItemAttr;
	att2[0].data = [keyGUID UTF8String];
	att2[0].length = strlen(att2[0].data);
	att2[1].tag = kSecCommentItemAttr;
	att2[1].data = "Added by The Password Utility";
	att2[1].length = strlen(att2[1].data);
	list2.attr = att2;
	
	OSStatus status_4 = SecKeychainItemModifyAttributesAndData(itemRef, &list2, 0, NULL);
	if(status_4 != noErr) {
		NSLog(@"Could not append attributes to keychain");
		ret_code = 1;
		goto end1;
	}
	
end1:
	if(accessRef) CFRelease(accessRef);
end2:
	if(itemRef) CFRelease(itemRef);
end3:
	if(ret_code == 0) {
		NSLog(@"Keychain written successfully");
	} else {
		NSLog(@"Keychain not written successfully");
	}

	// Garbage collection
	[pool release];
	return ret_code;
}
