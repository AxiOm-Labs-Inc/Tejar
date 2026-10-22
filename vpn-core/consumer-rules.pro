# SnakeYAML (Clash subscriptions) mentions java.beans for bean-style loading, which Android
# lacks. ClashSubscriptionParser uses SafeConstructor only (plain Maps and Lists), so the
# bean paths are never reached and nothing needs keeping by reflection.
-dontwarn java.beans.**
