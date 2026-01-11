/**
 * Gulp build configuration for n8n-ethereum-secure
 */

const gulp = require("gulp");

/**
 * Copy SVG icons to dist folder
 */
function copyIcons() {
  return gulp
    .src("nodes/**/*.svg")
    .pipe(gulp.dest("dist/nodes"));
}

/**
 * Copy all assets to dist
 */
function copyAssets() {
  return gulp
    .src(["nodes/**/*.png", "nodes/**/*.jpg"])
    .pipe(gulp.dest("dist/nodes"));
}

/**
 * Build icons task
 */
const buildIcons = gulp.parallel(copyIcons, copyAssets);

exports["build:icons"] = buildIcons;
exports.default = buildIcons;
