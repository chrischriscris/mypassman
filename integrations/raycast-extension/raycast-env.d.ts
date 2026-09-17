/// <reference types="@raycast/api">

/* 🚧 🚧 🚧
 * This file is auto-generated from the extension's manifest.
 * Do not modify manually. Instead, update the `package.json` file.
 * 🚧 🚧 🚧 */

/* eslint-disable @typescript-eslint/ban-types */

type ExtensionPreferences = {
  /** mypassman Binary Path - Path to the mypassman binary (~ is expanded) */
  "binaryPath": string
}

/** Preferences accessible in all the extension's commands */
declare type Preferences = ExtensionPreferences

declare namespace Preferences {
  /** Preferences accessible in the `list-items` command */
  export type ListItems = ExtensionPreferences & {}
}

declare namespace Arguments {
  /** Arguments passed to the `list-items` command */
  export type ListItems = {}
}

