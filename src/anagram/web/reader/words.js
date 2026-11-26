// The words of the reading view. One place, so that a node page (the local
// UI, later the guest page) can give its own words with the same keys.
// Rules: ASD-STE100 simple English; say a thing one time; no ids on screen.

export const WORDS = {
  contents: 'Files',
  facts: 'About this finding',
  byline: 'Shared by {name}',
  byline_on: 'Shared by {name} on {date}',
  a_member: 'A member',
  version: 'Version',
  proven: 'Proven to exist by',
  checked: 'These are the files that the owner committed. Anagram checked each file against the proof.',
  not_checked: 'Anagram did not check these files against the proof.',
  details: 'Details',
  root: 'Finding root',
  includes: {
    one: 'This finding includes 1 more finding. It is in Shared with me.',
    other: 'This finding includes {n} more findings. They are in Shared with me.',
  },
  open_original: 'Open the original',
  save_copy: 'Save a copy',
  kinds: {
    pdf: 'PDF',
    image: 'Image',
    table: 'Table',
    text: 'Text',
    document: 'Document',
    slides: 'Slides',
    file: 'File',
    notebook: 'Notebook',
    code: 'Code',
  },
  pages: { one: '1 page', other: '{n} pages' },
  slides_n: { one: '1 slide', other: '{n} slides' },
  rows: { one: '1 row', other: '{count} rows' },
  rows_shown: 'The first {shown} of {total} rows are here. The original file has all rows.',
  page_of: 'Page {n} of {total}',
  slide_of: 'Slide {n} of {total}',
  previous_page: 'Previous page',
  next_page: 'Next page',
  previous_slide: 'Previous slide',
  next_slide: 'Next slide',
  page_label: 'Page {n}',
  slide_label: 'Slide {n}',
  loading_pdf: 'Opening the PDF.',
  pdf_failed: 'This PDF does not show here. Open the original file to read it. The text of the file is below.',
  pdf_failed_empty: 'This PDF does not show here. Open the original file to read it.',
  figures: 'Figures in this file',
  figure_n: 'Figure {n}',
  output: 'Output',
  truncated: 'Open the original file to see all figures.',
  no_preview: 'This type of file does not show here. Save a copy to open it in another app.',
  empty_item: 'This file has no text to show.',
  empty: 'This finding has no files to show.',
  next_file: 'Next file: {name}',
  bytes: { b: '{n} bytes', kb: '{n} KB', mb: '{n} MB', gb: '{n} GB' },
  months: [
    'January',
    'February',
    'March',
    'April',
    'May',
    'June',
    'July',
    'August',
    'September',
    'October',
    'November',
    'December',
  ],
  // The standalone page (index.html).
  back: 'Shared with me',
  opening: 'Opening the finding.',
  open_failed: 'This finding does not open now. Go back to Shared with me and try again.',
  no_finding: 'This page needs a finding. Open a finding from Shared with me.',
};

/** The text of a key with its parameters. A {one, other} value takes `n`. */
export function say(words, key, params = {}) {
  let value = key.split('.').reduce((v, part) => (v == null ? v : v[part]), words);
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    value = params.n === 1 ? value.one : value.other;
  }
  if (typeof value !== 'string') return key;
  return value.replace(/\{(\w+)\}/g, (m, name) => (name in params ? String(params[name]) : m));
}
