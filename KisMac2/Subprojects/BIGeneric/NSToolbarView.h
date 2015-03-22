/*
 *  NSToolbarView.h
 *  BIGeneric
 *
 *  Created by mick on Fri Jul 02 2004.
 *  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
 *
 */

#include <AppKit/AppKit.h>

struct __tbvFlags {
    unsigned int _layoutInProgress:1;
    unsigned int _sizingToFit:1;
    unsigned int _isEditing:1;
    unsigned int _inCustomizationMode:1;
    unsigned int _sourceDragMoves:1;
    unsigned int _enabledAsDragSrc:1;
    unsigned int _enabledAsDragDest:1;
    unsigned int _actingAsPalette:1;
    unsigned int _usePaletteLabels:1;
    unsigned int _validatesItems:1;
    unsigned int _forceItemsToBeMinSize:1;
    unsigned int _forceAllClicksToBeDrags:1;
    unsigned int _wrapsItems:1;
    unsigned int _useGridAlignment:1;
    unsigned int _autosizesToFitHorizontally:1;
    unsigned int transparentBackground:1;
    unsigned int drawsBaseline:1;
    unsigned int shouldOverrideHalftonePhase:1;
    unsigned int weStartedDrag:1;
    unsigned int dragOptimizationOn:1;
    unsigned int dragIsInsideView:1;
    unsigned int insertionOptimizationShouldEndAfterUpdates:1;
    unsigned int wantsKeyboardLoop:1;
    unsigned int clipIndicatorWasFirstResponder:1;
    unsigned int scheduledDelayedValidateVisibleItems:1;
    unsigned int skippedLayoutWhileDisabled:1;
    unsigned int shouldHideAfterKeyboardHotKeyEvent:1;
    unsigned int RESERVED:5;
};

@interface NSToolbarClippedItemsIndicator : NSPopUpButton
{
    NSArray *_clippedItems;
    BOOL _cachedMenuIsValid;
}

+ (void)initialize;
+ (BOOL)isItemShownInPopupIfSoleEntry:(id)fp8;
+ (BOOL)willHaveItemsToDisplayForItemViewers:(id)fp8;
- (id)_clipViewAncestor;
- (void)_computeMenuForClippedItems;
- (void)_computeMenuForClippedItemsIfNeeded;
- (void)_initClipIndicatorImage;
- (void)_simpleOverflowMenuItemClicked:(id)fp8;
- (void)_updateMenuForClippedItems;
- (void)_willPopUpNotification:(id)fp8;
- (BOOL)acceptsFirstResponder;
- (BOOL)becomeFirstResponder;
- (void)becomeKeyWindow;
- (id)clippedItems;
- (void)dealloc;
- (void)drawRect:(struct _NSRect)fp8;
- (BOOL)hasItemsToDisplayInPopUp;
- (id)init;
- (void)mouseDown:(id)fp8;
- (void)moveLeft:(id)fp8;
- (void)moveRight:(id)fp8;
- (BOOL)needsPanelToBecomeKey;
- (void)performClick:(id)fp8;
- (BOOL)resignFirstResponder;
- (void)resignKeyWindow;
- (void)setClippedItems:(id)fp8;
- (BOOL)validateMenuItem:(id)fp8;

@end

@interface NSToolbarView : NSView
{
    NSToolbar *_toolbar;
    NSToolbarClippedItemsIndicator *_clipIndicator;
    NSClipView *_ivClipView;
    NSMutableDictionary *_toolbarItemViewersByItem;
    NSMutableArray *_orderedItemViewers;
    NSToolbarItemViewer *_dragDataItemViewer;
    int _dragDataItemViewerStartIndex;
    BOOL _dragDataItemShouldBeRemoved;
    NSToolbarItemViewer *_dragDataInsertionGapItemViewer;
    struct _NSPoint _dragDataLastPoint;
    BOOL _insertionAnimationRunning;
    struct _NSPoint _halftonePhaseOverrideValue;
    NSToolbarView *_validDestinationForDragsWeInitiate;
    int _layoutEnabledCount;
    struct __tbvFlags _tbvFlags;
    NSResponder *_windowPriorFirstResponder;
}

+ (id)defaultMenu;
+ (id)newViewForToolbar:(id)fp8 inWindow:(id)fp12 attachedToEdge:(int)fp16;
- (void)_adjustClipIndicatorPosition;
- (id)_allItems;
- (void)_beginCustomizationMode;
- (void)_beginTempEditingMode;
- (id)_clipIndicator;
- (BOOL)_clipIndicatorIsShowing;
- (id)_clippedItemViewers;
- (id)_computeCommonItemViewers;
- (id)_computeCustomItemViewers;
- (id)_computeCustomItemViewersInRange:(struct _NSRange)fp8;
- (id)_computeOrderedItemViewersOfType:(int)fp8;
- (id)_computeOrderedItemViewersOfType:(int)fp8 inRange:(struct _NSRange)fp12;
- (id)_computePriorFirstResponder;
- (void)_computeToolbarItemKeyboardLoop;
- (void)_computeToolbarItemKeyboardLoopIfNecessary;
- (void)_createClipIndicatorIfNecessary;
- (void)_cycleWindows:(id)fp8;
- (void)_detatchNextAndPreviousForAllSubviews;
- (void)_detatchNextAndPreviousForView:(id)fp8;
- (void)_disableLayout;
- (float)_distanceFromBaseToTopOfWindow;
- (void)_doDelayedValidateVisibleToolbarItems;
- (void)_drawForTransitionInWindow:(id)fp8 usingHalftonePhaseForWindowOfSize:(struct _NSSize)fp12;
- (void)_enableLayout;
- (void)_endCustomizationMode;
- (void)_endLiveResize;
- (id)_findHitItemViewer:(struct _NSPoint)fp8;
- (void)_forceResetTexturedWindowDragMargins;
- (void)_fullLayout;
- (BOOL)_inTexturedWindow;
- (BOOL)_isEditing;
- (BOOL)_isInConfigurationMode;
- (BOOL)_isInCustomizationMode;
- (BOOL)_isPaletteView;
- (id)_itemsFromItemViewers:(id)fp8;
- (void)_layoutDirtyItemViewersAndTileToolbar;
- (BOOL)_layoutEnabled;
- (int)_layoutRowStartingAtIndex:(int)fp8 withFirstItemPosition:(struct _NSPoint)fp12 allItemViewers:(id)fp20 gridWidth:(int)fp24;
- (void)_makeFirstResponderForKeyboardHotKeyEvent;
- (void)_makeSureFirstResponderIsNotInInvisibleItemViewer;
- (void)_makeSureItemViewersInArray:(id)fp8 areSubviews:(BOOL)fp12 from:(int)fp16 to:(int)fp20;
- (void)_noteToolbarDisplayModeChanged;
- (void)_noteToolbarLayoutChanged;
- (void)_noteToolbarModeChangedAndUpdateItemViewers:(SEL)fp8;
- (void)_noteToolbarSizeModeChanged;
- (void)_removeClipIndicatorFromSuperview;
- (void)_returnFirstResponderToWindowFromKeyboardHotKeyEvent;
- (void)_setActsAsPalette:(BOOL)fp8 forToolbar:(id)fp12;
- (void)_setAllItemsTransparentBackground:(BOOL)fp8;
- (void)_setAllowsMultipleRows:(BOOL)fp8;
- (void)_setClipIndicatorItemsFromItemViewers:(id)fp8;
- (void)_setDrawsBaseline:(BOOL)fp8;
- (void)_setForceItemsToBeMinSize:(BOOL)fp8;
- (void)_setFrameSize:(struct _NSSize)fp8;
- (void)_setNeedsDisplayForItemIdentifierSelection:(id)fp8;
- (void)_setNeedsDisplayForItemViewerSelection:(id)fp8;
- (void)_setNeedsModeConfiguration:(BOOL)fp8 itemViewers:(id)fp12;
- (void)_setNeedsViewerLayout:(BOOL)fp8 itemViewers:(id)fp12;
- (void)_setWantsKeyboardLoop:(BOOL)fp8;
- (BOOL)_shouldStealHitTestForCurrentEvent;
- (void)_sizeHorizontallyToFit;
- (void)_sizeToFit:(BOOL)fp8;
- (void)_sizeVerticalyToFit;
- (void)_syncItemSet;
- (struct CGSize)_toolbarPatternPhase;
- (void)_toolbarViewCommonInit;
- (id)_validDestinationForDragsWeInitiate;
- (struct _NSRect)_validItemViewerBounds;
- (struct _NSRect)_validItemViewerBoundsAssumingClipIndicatorNotShown;
- (struct _NSRect)_validItemViewerBoundsAssumingClipIndicatorShown;
- (void)_validateVisibleToolbarItems;
- (id)_visibleItemViewers;
- (BOOL)_wantsKeyboardLoop;
- (BOOL)acceptsFirstMouse:(id)fp8;
- (id)clippedItems;
- (void)dealloc;
- (id)description;
- (void)drawRect:(struct _NSRect)fp8;
- (id)hitTest:(struct _NSPoint)fp8;
- (id)initWithFrame:(struct _NSRect)fp8;
- (BOOL)isFlipped;
- (BOOL)isOpaque;
- (id)menuForEvent:(id)fp8;
- (void)mouseDown:(id)fp8;
- (BOOL)mouseDownCanMoveWindow;
- (int)numberOfItems;
- (void)removeToolbarItem:(id)fp8;
- (void)resetToolbarToDefaultConfiguration:(id)fp8;
- (void)setFrameSize:(struct _NSSize)fp8;
- (void)setToolbar:(id)fp8;
- (id)toolbar;
- (BOOL)validateMenuItem:(id)fp8;
- (void)viewDidMoveToSuperview;
- (void)viewWillMoveToWindow:(id)fp8;
- (id)visibleItems;
- (void)windowDidUpdate:(id)fp8;

@end

@interface NSToolbarView (NSToolbarViewAccessibility)
- (id)accessibilityAttributeNames;
- (id)accessibilityChildrenAttribute;
- (BOOL)accessibilityIsIgnored;
- (BOOL)accessibilityIsOverflowButtonAttributeSettable;
- (id)accessibilityOverflowButtonAttribute;
- (id)accessibilityRoleAttribute;
@end

@interface NSToolbarView (_ItemDragAndDropSupport)
- (BOOL)_beginSrcDragItemViewerWithEvent:(id)fp8;
- (BOOL)_beginSrcDragItemWithEvent:(id)fp8;
- (BOOL)_canMoveItemAsSource:(id)fp8;
- (id)_computeDragImageFromItemViewer:(id)fp8;
- (float)_computeTravelTimeForInsertionOfItemViewer:(id)fp8;
- (id)_dragDataItemViewer;
- (void)_dragEndedNotification:(id)fp8;
- (void)_dstDraggingExitedAtPoint:(struct _NSPoint)fp8 draggingInfo:(id)fp16 stillInViewBounds:(BOOL)fp20;
- (void)_endInsertionOptimizationWithDragSource:(id)fp8 force:(BOOL)fp12;
- (unsigned int)_findIndexOfFirstDuplicateItemWithItemIdentier:(id)fp8;
- (id)_findItemViewerAtPoint:(struct _NSPoint)fp8;
- (id)_insertionGapForItemViewer:(id)fp8 forDraggingSource:(id)fp12;
- (int)_insertionIndexForPoint:(struct _NSPoint)fp8 previousIndex:(int)fp16;
- (BOOL)_isAcceptableDragSource:(id)fp8 types:(id)fp12 dragInfo:(id)fp16;
- (BOOL)_isItemViewerMoveable:(id)fp8;
- (id)_itemViewerForDraggingInfo:(id)fp8 draggingSource:(id)fp12;
- (struct _NSRect)_rectOfItemAtIndex:(int)fp8;
- (void)_startInsertionOptimizationWithDragSource:(id)fp8;
- (void)_updateDragInsertion:(id)fp8;
- (BOOL)acceptsFirstMouse:(id)fp8;
- (void)beginUpdateInsertionAnimationAtIndex:(int)fp8 throwAwayCacheWhenDone:(BOOL)fp12;
- (unsigned int)draggingEntered:(id)fp8;
- (void)draggingExited:(id)fp8;
- (unsigned int)draggingSourceOperationMaskForLocal:(BOOL)fp8;
- (unsigned int)draggingUpdated:(id)fp8;
- (BOOL)dstDraggingDepositedAtPoint:(struct _NSPoint)fp8 draggingInfo:(id)fp16;
- (unsigned int)dstDraggingEnteredAtPoint:(struct _NSPoint)fp8 draggingInfo:(id)fp16;
- (void)dstDraggingExitedAtPoint:(struct _NSPoint)fp8 draggingInfo:(id)fp16;
- (unsigned int)dstDraggingMovedToPoint:(struct _NSPoint)fp8 draggingInfo:(id)fp16;
- (void)insertItemViewer:(id)fp8 atIndex:(int)fp12;
- (BOOL)performDragOperation:(id)fp8;
- (void)removeItemViewerAtIndex:(int)fp8;
- (void)stopUpdateInsertionAnimation;
@end

@interface NSToolbarView (_NSPrivate_Internal)
- (void)_registerForToolbarNotifications:(id)fp8;
- (void)_toolbarAttributesChanged:(id)fp8;
- (void)_toolbarContentsAttributesChanged:(id)fp8;
- (void)_toolbarContentsChanged:(id)fp8;
- (void)_unregisterForToolbarNotifications:(id)fp8;
@end

@interface _NSToolbarItemViewerLabelCellPopUpCell : NSPopUpButtonCell
{
    NSString *_realTitle;
}

- (void)_drawRealTitleWithFrame:(struct _NSRect)fp8 inView:(id)fp24;
- (void)_setRealTitle:(id)fp8;
- (void)_setTextShadow:(BOOL)fp8;
- (id)_sharedTextCell;
- (int)alignment;
- (void)beginUsingMenuRepresentation:(id)fp8;
- (struct _NSSize)cellSizeForBounds:(struct _NSRect)fp8;
- (void)dealloc;
- (void)drawInteriorWithFrame:(struct _NSRect)fp8 inView:(id)fp24;
- (void)drawTitleWithFrame:(struct _NSRect)fp8 inView:(id)fp24;
- (void)finishUsingMenuRepresentation;
- (id)initTextCell:(id)fp8;
- (void)performClickWithFrame:(struct _NSRect)fp8 inView:(id)fp24;
- (void)setCellAttribute:(int)fp8 to:(int)fp12;
- (void)setStringValue:(id)fp8;
- (void)setTitle:(id)fp8;
- (id)title;
- (struct _NSRect)titleRectForBounds:(struct _NSRect)fp8;

@end

@interface NSToolbarItemViewer : NSView
{
    NSToolbarItem *_item;
    NSToolbarView *_toolbarView;
    _NSToolbarItemViewerLabelCellPopUpCell *_labelCell;
    struct _NSRect _labelRect;
    float _labelHeight;
    struct _NSSize _maxViewerSize;
    struct _NSSize _minViewerSize;
    struct _NSRect _minIconFrame;
    struct _NSRect _minLabelFrame;
    double _motionStartTime;
    double _motionDuration;
    struct _NSPoint _motionStartLocation;
    struct _NSPoint _motionDestLocation;
    struct {
        unsigned int drawsIconPart:1;
        unsigned int drawsLabelPart:1;
        unsigned int iconAreaIncludesLabelArea:1;
        unsigned int transparentBackground:1;
        unsigned int labelOnlyShowsAsPopupMenu:1;
        unsigned int inMotion:1;
        unsigned int inRecursiveDisplay:1;
        unsigned int insertionAnimationOptimizationOn:1;
        unsigned int needsViewerLayout:1;
        unsigned int needsModeConfiguration:1;
        unsigned int inPaletteView:1;
        unsigned int UNUSED:21;
    } _tbivFlags;
}

- (BOOL)_acceptsFirstResponderInItem:(id)fp8;
- (void)_beginToolbarEditingMode;
- (void)_captureVisibleIntoImageCache;
- (void)_captureVisibleIntoLiveResizeCache;
- (void)_computeLayoutInfoForIconViewSize:(struct _NSSize)fp8 frameSize:(struct _NSSize *)fp16 iconFrame:(struct _NSRect *)fp20 labelFrame:(struct _NSRect *)fp24;
- (void)_configureLabelCellStringValue;
- (void)_drawHighlighted:(BOOL)fp8;
- (void)_drawWithImageCache;
- (void)_endInsertionOptimization;
- (void)_endToolbarEditingMode;
- (BOOL)_hasImageCache;
- (BOOL)_heightIsFlexible;
- (void)_itemChanged;
- (void)_itemChangedLabelOrPaletteLabel;
- (void)_itemChangedToolTip;
- (void)_itemLayoutChanged;
- (void)_labelCellWillDismissNotification:(id)fp8;
- (void)_labelCellWillPopUpNotification:(id)fp8;
- (BOOL)_labelOnlyShowsAsPopupMenu;
- (void)_menuFormRepresentationChanged;
- (BOOL)_needsModeConfiguration;
- (BOOL)_needsViewerLayout;
- (void)_noteToolbarSizeModeChanged;
- (void)_recomputeLabelHeight;
- (void)_recursiveDisplayAllDirtyWithLockFocus:(BOOL)fp8 visRect:(struct _NSRect)fp12;
- (void)_setDefaultKeyViewLoop;
- (void)_setHighlighted:(BOOL)fp8 displayNow:(BOOL)fp12;
- (void)_setNeedsModeConfiguration:(BOOL)fp8;
- (void)_setNeedsViewerLayout:(BOOL)fp8;
- (void)_setToolbarItem:(id)fp8;
- (BOOL)_shouldDrawSelectionIndicator;
- (BOOL)_shouldLiveResizeUseCachedImage;
- (void)_startInsertionOptimization;
- (BOOL)_useSquareToolbarSelectionHighlight;
- (BOOL)_wantsLiveResizeToUseCachedImage;
- (BOOL)_widthIsFlexible;
- (float)_widthRequiredForLabelLayout;
- (BOOL)acceptsFirstMouse:(id)fp8;
- (BOOL)acceptsFirstResponder;
- (BOOL)becomeFirstResponder;
- (void)becomeKeyWindow;
- (void)configureForLayoutInDisplayMode:(int)fp8 andSizeMode:(int)fp12 inToolbarView:(id)fp16;
- (void)dealloc;
- (id)description;
- (struct _NSPoint)destination;
- (void)drawRect:(struct _NSRect)fp8;
- (void)drawSelectionIndicatorInRect:(struct _NSRect)fp8;
- (id)hitTest:(struct _NSPoint)fp8;
- (id)initWithItem:(id)fp8 forToolbarView:(id)fp12;
- (BOOL)isInMotion;
- (BOOL)isOpaque;
- (id)item;
- (void)layoutToFitInIconWidth:(double)fp8;
- (void)layoutToFitInMinimumIconSize;
- (void)layoutToFitInViewerFrameHeight:(double)fp8;
- (struct _NSSize)maxSize;
- (void)mouseDown:(id)fp8;
- (BOOL)mouseDownCanMoveWindow;
- (void)moveLeft:(id)fp8;
- (void)moveRight:(id)fp8;
- (BOOL)needsPanelToBecomeKey;
- (void)performClick:(id)fp8;
- (BOOL)resignFirstResponder;
- (void)resignKeyWindow;
- (void)setDestinationOrigin:(struct _NSPoint)fp8 travelTimeInSeconds:(double)fp16;
- (void)setTransparentBackground:(BOOL)fp8;
- (void)stepTowardsDestinationAtleastAsFarAs:(double)fp8;
- (BOOL)transparentBackground;

@end

@interface NSToolbarItemViewer (NSToolbarItemViewerAccessibility)
- (int)_accessibilityCellLabelType;
- (BOOL)_accessibilityIconHandlesTitle;
- (id)accessibilityAttributeNames;
- (id)accessibilityChildrenAttribute;
- (id)accessibilityHelpStringForChild:(id)fp8;
- (id)accessibilityHitTest:(struct _NSPoint)fp8;
- (BOOL)accessibilityIsChildFocusable:(id)fp8;
- (BOOL)accessibilityIsIgnored;
- (BOOL)accessibilityIsTitleUIElementAttributeSettable;
- (id)accessibilityPositionOfChild:(id)fp8;
- (id)accessibilityRoleAttribute;
- (id)accessibilitySizeOfChild:(id)fp8;
- (id)accessibilityTitleUIElementAttribute;
@end

