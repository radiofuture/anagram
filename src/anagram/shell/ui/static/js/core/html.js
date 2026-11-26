// The one file that imports the vendored modules (static/vendor). Screens and
// components import from this file, so a change of library touches one file.
// The import map in index.html resolves the bare names.
import { h, render, Fragment, createContext } from 'preact';
import { useState, useEffect, useLayoutEffect, useRef, useMemo, useCallback, useContext, useId } from 'preact/hooks';
import htm from 'htm';
import { signal, computed, effect, batch, untracked, useSignal, useComputed, useSignalEffect } from '@preact/signals';

// Tagged template to virtual nodes. Text is always put in the page as text.
export const html = htm.bind(h);

export {
  h,
  render,
  Fragment,
  createContext,
  useState,
  useEffect,
  useLayoutEffect,
  useRef,
  useMemo,
  useCallback,
  useContext,
  useId,
  signal,
  computed,
  effect,
  batch,
  untracked,
  useSignal,
  useComputed,
  useSignalEffect,
};
