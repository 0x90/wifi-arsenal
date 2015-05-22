/*
 *  NSToolbar.h
 *  BIGeneric
 *
 *  Created by mick on Fri Jul 02 2004.
 *  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
 *
 */

#include <AppKit/AppKit.h>

@interface NSToolbar(PrivateExtension) 
+ (BOOL)_allowSmallIcons;
+ (id)_newPlaceholderItemWithItemIdentifier:(id)fp8;
+ (id)_newStandardItemWithItemIdentifier:(id)fp8;
+ (id)_newUnknownItemWithItemIdentifier:(id)fp8;
+ (void)_registerToolbarInstance:(id)fp8;
+ (void)_unregisterToolbarInstance:(id)fp8;
- (id)_allowedItemIdentifiers;
- (BOOL)_allowsDuplicateItems;
- (void)_appendNewItemWithItemIdentifier:(id)fp8 notifyDelegate:(BOOL)fp12 notifyView:(BOOL)fp16 notifyFamilyAndUpdateDefaults:(BOOL)fp20;
- (void)_autoSaveCofiguration;
- (id)_backgroundColor;
- (BOOL)_canRunCustomizationPanel;
- (void)_checkForObsoleteDelegateMethodsInObject:(id)fp8;
- (void)_configSheetDidEnd:(id)fp8 returnCode:(int)fp12 contextInfo:(void *)fp16;
- (id)_configurationAutosaveName;
- (id)_createItemFromItemIdentifier:(id)fp8;
- (id)_customizationPaletteSheetWindow;
- (BOOL)_customizesAlwaysOnClickAndDrag;
- (id)_defaultItemIdentifiers;
- (void)_destroyToolbarAssociation:(id)fp8;
- (id)_dictionaryForSavedConfiguration;
- (void)_disableNotifications;
- (void)_enableNotifications;
- (void)_endCustomizationPalette:(id)fp8;
- (void)_endCustomizationPanel;
- (id)_findFirstItemInArray:(id)fp8 withItemIdentifier:(id)fp12;
- (int)_firstMoveableItemIndex;
- (void)_forceAppendItem:(id)fp8;
- (void)_forceInsertItem:(id)fp8 atIndex:(int)fp12;
- (void)_forceMoveItemFromIndex:(int)fp8 toIndex:(int)fp12;
- (void)_forceRemoveItemFromIndex:(int)fp8;
- (void)_forceReplaceItemAtIndex:(int)fp8 withItem:(id)fp12;
- (void)_hide:(id)fp8;
- (void)_insertNewItemWithItemIdentifier:(id)fp8 atIndex:(int)fp12 notifyDelegate:(BOOL)fp16 notifyView:(BOOL)fp20 notifyFamilyAndUpdateDefaults:(BOOL)fp24;
- (BOOL)_isEditing;
- (BOOL)_isSelectableItemIdentifier:(id)fp8;
- (id)_itemAtIndex:(int)fp8;
- (id)_items;
- (BOOL)_keyboardLoopNeedsUpdating;
- (void)_loadAllPlaceholderItems;
- (void)_loadFromUDIfNecessary;
- (void)_loadInitialItemIdentifiers:(id)fp8 requireImmediateLoad:(BOOL)fp12;
- (void)_loadViewIfNecessary;
- (void)_makeFirstResponderForKeyboardHotKeyEvent;
- (void)_makeNewToolbarAssociation:(id)fp8;
- (void)_moveItemFromIndex:(int)fp8 toIndex:(int)fp12 notifyDelegate:(BOOL)fp16 notifyView:(BOOL)fp20 notifyFamilyAndUpdateDefaults:(BOOL)fp24;
- (id)_newItemFromDelegateWithItemIdentifier:(id)fp8 willBeInsertedIntoToolbar:(BOOL)fp12;
- (id)_newItemFromInitPListWithItemIdentifier:(id)fp8;
- (id)_newItemFromItemIdentifier:(id)fp8 requireImmediateLoad:(BOOL)fp12 willBeInsertedIntoToolbar:(BOOL)fp16;
- (void)_newToolbarBornNotification:(id)fp8;
- (int)_nextDisplayMode;
- (void)_noteToolbarDisplayModeChangedAndPost:(id)fp8;
- (void)_noteToolbarSizeModeChangedAndPost:(id)fp8;
- (BOOL)_notificationPostingEnabled;
- (void)_notifyDelegate_DidRemoveItem:(id)fp8;
- (void)_notifyDelegate_DidRemoveItems:(id)fp8;
- (void)_notifyDelegate_WillAddItem:(id)fp8;
- (void)_notifyFamily_DidRemoveItemAtIndex:(int)fp8;
- (void)_notifyFamily_DidSetAllCurrentItems:(id)fp8;
- (void)_notifyFamily_InsertedNewItem:(id)fp8 atIndex:(int)fp12;
- (void)_notifyFamily_MovedFromIndex:(int)fp8 toIndex:(int)fp12;
- (void)_notifyView_DidRemoveItemAtIndex:(int)fp8;
- (void)_notifyView_DidSetAllCurrentItems:(id)fp8;
- (void)_notifyView_InsertedNewItem:(id)fp8 atIndex:(int)fp12;
- (void)_notifyView_MovedFromIndex:(int)fp8 toIndex:(int)fp12;
- (int)_numberOfItems;
- (void)_postDidCreateToolbarNotifications;
- (void)_postWillDeallocToolbarNotifications;
- (BOOL)_prefersToBeShown;
- (int)_previousDisplayMode;
- (void)_removeItemAtIndex:(int)fp8 notifyDelegate:(BOOL)fp12 notifyView:(BOOL)fp16 notifyFamilyAndUpdateDefaults:(BOOL)fp20;
- (void)_replaceAllItemsAndSetNewWithItemIdentifiers:(id)fp8;
- (void)_runCustomizationPanel;
- (BOOL)_sanityCheckPListDatabase:(id)fp8;
- (void)_saveConfigurationUsingName:(id)fp8 domain:(id)fp12;
- (BOOL)_setConfigurationFromDictionary:(id)fp8 notifyFamilyAndUpdateDefaults:(BOOL)fp12;
- (BOOL)_setConfigurationUsingName:(id)fp8 domain:(id)fp12;
- (void)_setCurrentItemsToItemIdentifiers:(id)fp8 notifyDelegate:(BOOL)fp12 notifyView:(BOOL)fp16 notifyFamilyAndUpdateDefaults:(BOOL)fp20;
- (void)_setCustomizesAlwaysOnClickAndDrag:(BOOL)fp8;
- (void)_setEnableDelegateNotifications:(BOOL)fp8;
- (void)_setFirstMoveableItemIndex:(int)fp8;
- (void)_setKeyboardLoopNeedsUpdating:(BOOL)fp8;
- (void)_setNeedsDisplayForItemIdentifierSelection:(id)fp8;
- (void)_setNextSizeAndDisplayMode;
- (void)_setPreviousSizeAndDisplayMode;
- (void)_setToolbarView:(id)fp8;
- (void)_setToolbarViewWindow:(id)fp8;
- (void)_setWantsToolbarContextMenu:(BOOL)fp8;
- (void)_show:(id)fp8;
- (BOOL)_sizeModeIsValidForCurrentDisplayMode:(int)fp8;
- (void)_toggleShown:(id)fp8;
- (void)_toolbarCommonBeginInit;
- (void)_toolbarCommonFinishInit;
- (void)_toolbarInsertedNewItemNotification:(id)fp8;
- (void)_toolbarModeChangedNotification:(id)fp8;
- (void)_toolbarMovedItemNotification:(id)fp8;
- (void)_toolbarRegisterForNotifications;
- (void)_toolbarRemovedItemNotification:(id)fp8;
- (void)_toolbarReplacedAllItemsNotification:(id)fp8;
- (void)_toolbarUnregisterForNotifications;
- (id)_toolbarView;
- (void)_toolbarWillDeallocNotification:(id)fp8;
- (void)_userInsertItemWithItemIdentifier:(id)fp8 atIndex:(int)fp12;
- (void)_userMoveItemFromIndex:(int)fp8 toIndex:(int)fp12;
- (void)_userRemoveItemAtIndex:(int)fp8;
- (void)_userResetToDefaultConfiguration;
- (void)_userSetCurrentItemsToItemIdentifiers:(id)fp8;
- (BOOL)_wantsToolbarContextMenu;
- (void)_windowDidHideToolbar;
- (void)_windowWillShowToolbar;
@end
