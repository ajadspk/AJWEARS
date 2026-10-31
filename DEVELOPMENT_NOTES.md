# Development notes

The homepage uses the supplied campaign/category assets rather than substituting unrelated stock photos.

The supplied asset pack already contains the complete visual campaign artwork for the hero and service strip. The implementation therefore:
- uses the exact hero visual as the right-side hero artwork,
- rebuilds the left typography/buttons in live HTML for responsiveness and interaction,
- uses the exact service strip artwork on desktop,
- switches to live responsive service cards on mobile,
- uses the six exact category assets for category navigation.

The product catalog is intentionally data-driven. Because the supplied asset pack does not contain separate SKU photography, the exact category campaign images are reused as product imagery. Replace each product's `image` value in the SQLite database or seed logic when individual product photos become available.
