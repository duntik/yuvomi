<!-- version: 2.77.2 -->
This update makes the app start again on 64-bit ARM devices and brings a few budget and subscription fixes.

On ARM-based systems the 2.77.1 image stopped right at startup because two libraries were missing from it. They are back, and every image is now checked for its libraries on each platform before it is published.

Subscriptions with an end behave as expected: the last payment stays in the budget, a completed subscription can no longer be marked as paid again, and switching one back on continues with the payment after the last one instead of booking it twice. A private subscription no longer shows its expense in the household budget when two changes meet. The budget overview shows each category's share of the total, and error messages on the recipes, documents and subscriptions pages now speak the language of the app.

No database migration and no action is needed. As always, a backup before updating is a good idea.

Full release notes are available at https://github.com/ulsklyc/yuvomi/releases/tag/v2.77.2
