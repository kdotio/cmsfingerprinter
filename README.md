# Idea

The idea behind this project is to fingerprint the version of a CMS.

This is done by requesting specific files, hashing them and comparing them to hashes from known releases. Depending on the website this process may be as quick as requesting a single file. This version can then be used for identifying known vulnerabilities (CVE).

The purpose of this tool is usage in pentesting.

# Usage

As of now, the user must have basic knowledge which specific CMS is used. There are various other tools available that do this just fine.

```
go run . -target <target> -cms <cms>
-cms value must match filename in ./hashes dir
```

```
go run . -target https://example.local -cms wordpress

Succesfully parsed hashes.
Analyzing https://example.local
---------
(200) https://example.local/readme.html [5f5f739bee08d0ac236d3409a40e4e37]
Found tags: [6.0.1 6.0]
Currently (2) possible versions: [6.0.1 6.0]
---------
(200) https://example.local/wp-includes/js/dist/block-library.js [0d152aadaba02d719774d459bb50563d]
Found tags: [6.0.1]
Currently (1) possible versions: [6.0.1]
SUCCESS. Found 6.0.1
```

## Getting started
```
fp, _ := fingerprinter.New(bytes)

tags, _ := fp.Analyze(ctx, target)

if len(tags) == 1 {
    log.Println("SUCCESS. Found", tags[0])
}
```

## Filehashes

The filehashes were generated using openly available repos as well as pre-packaged archives.

When hashing files using repos, a list of the 50-150 most changed files across all revisions was created that was hashed for each revision.
This greatly reduced the number of files to be hashed. However, this may lead to inconclusive results for some CMS or versions, as the overlap is too great.

If there is no public repo available, all files of each release had to be hashed for proper fingerprinting.

In any case, results may be inconclusive because the publicly readable files, e.g. `.html, .js, .css` might've not changed for some time
whereas non-readable files, e.g. `.php` were changed.

# Supported so far
* BoltCMS `0.8.4 - 3.7.4.1`
* Concrete CMS `5.7 - 9.0.1`
* Contao `3.2.12 - 4.5.10`
* Drupal `1.0 - 9.4.5`
* GravCMS `0.1 - 1.7.25`
* Joomla! `1.7.3 - 4.1.5`
* Laravel `3.2 - 8.6.7` // rather wide-ranging
* Magento1 Open Source `1.1.1 - 1.9.4.5`
* Magento2 Community Edition `2.0 - 2.4.3`
* Nextcloud `1.1 - 22.2.3`
* nopCommerce `2.0 - 4.40.4`
* OctoberCMS `1.0.319 - 2.1.20`
* OpenCart `1.5.5.1 - 3.0.3.8`
* OpenMageLTS `1.1.1 - 20.0.13`
* Owncloud `1.1 - 10.8`
* OXID eShop Community Edition `4.6.7 - 6.9`
* phpBB `2.0 - 3.3.5`
* phpMyAdmin `2.2 - 5.1.1`
* PrestaShop `1.5 - 1.7.8.1`
* Shopware `1.0.2 - 5.7.6`
* TYPO3 `3.6 - 11.5.2`
* Umbraco `4.9 - 9.1.2`
* WooCommerce `1.0 - 5.9` // note deployment path, i.e. /wp-content/plugins/woocommerce in -target
* WordPress `1.5 - 6.0.1`

# Disclaimer
This project can only be used for educational purposes. Using this software against target systems without prior permission is illegal, and any damages from misuse of this software will not be the responsibility of the author.