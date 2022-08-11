# Idea

The idea behind this project is to fingerprint CMS as well as other software components on a website
by hashing files and comparing them with hashes for specific releases.

Depending on the website this process may be as quick as requesting a single file.

The tool can be used for pentesting purposes to show that mere hiding of obvious version indicators, security by obscurity, is not enough to be safe.

# Usage

```
go run . -target https://example.com -cms wordpress

-cms value must match filename in ./hashes dir
```

As of now, the user must have basic knowledge which specific CMS is used.

This tool is can be used for finding version information where this is not obvious,
e.g. if no version is found in the `<meta name="generator" content="WordPress">` tag

The tool can also be used to fingerprint the specific semantic version (`major.minor.patch`), if only a major version is easily visible.

## Filehashes

The filehashes were generated using openly available GitHub repos as well as pre-packaged archives.

When hashing files using repos, a list of the 50-100 most changed files across all revisions was created that was hashed for each revision.
This greatly reduced the number of files to be hashed, but may lead to inconclusive results for some CMS or versions, as the overlap is too great.

If there is no public repo available, all files of each release had to be hashed for proper fingerprinting.

In any case, results may be inconclusive because the publicly readable files, e.g. `.html, .js, .css` might've not changed for some time
whereas non-readable files, e.g. `.php` were changed.

# Supported so far
* BoltCMS `0.8.4 - 3.7.4.1`
* Concrete CMS `5.7 - 9`
* Contao `3.2.12 - 4.5.10`
* Drupal `1 - 9.2.8`
* GravCMS `0.1 - 1.7.25`
* Joomla! `1.7.3 - 13.1`
* Laravel `3.2 - 8.6.7` // rather wide-ranging
* Magento1 Open Source `1.1.1 - 1.9.4.5`
* Magento2 Community Edition `2 - 2.4.3`
* Nextcloud `1.1 - 22.2.3`
* nopCommerce `2 - 4.40.4`
* OctoberCMS `1 - 2.1.20`
* OpenCart `1.5.5.1 - 3`
* OpenMageLTS `1.1.1 - 20`
* Owncloud `1.1 - 10.8`
* OXID eShop Community Edition `4.6.7 - 6.9`
* phpBB `2 - 3.3.5`
* phpMyAdmin `2.2 - 5.1.1`
* PrestaShop `1.5 - 1.7.8.1`
* Shopware `1 - 5.7.6`
* Shopware `6.4.6 - 6.4.7`
* TYPO3 `3.6 - 11.5.2`
* Umbraco `4.9 - 9.1.2`
* WooCommerce `1 - 5.9`
* WordPress `1.5 - 5.8.2`

# Disclaimer
This project can only be used for educational purposes. Using this software against target systems without prior permission is illegal, and any damages from misuse of this software will not be the responsibility of the author.