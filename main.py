from private_notes import PrivNotes

import re

def error(s):
  print('=== ERROR: %s' % s)

print('Initializing notes')
priv_notes = PrivNotes('123456')

print('Adding notes')
kvs = { 'Groceries': 'lettuce\nbread\nchocolate',
        'Idea': 'We will take a forklift to the moon!',
        'Secrets': 'The secret word is bananas.' }
for title in kvs:
  priv_notes.set(title, kvs[title])

print('Trying to fetch notes')
for title in kvs:
  note = priv_notes.get(title)
  if note != kvs[title]:
    error('get failed for title %s (expected %s, received %s)' % (title, kvs[title], note))
note = priv_notes.get('non-existent')
if note is not None:
  error('get failed for title non-existent (expected None, received %s)' % note)

print('Trying to remove notes')
if not priv_notes.remove('Groceries'):
  error('remove failed for title Groceries')
note = priv_notes.get('Groceries')
if note is not None:
  error('get failed for title Groceries (expected None, received %s)' % note)
if priv_notes.remove('non-existent'):
  error('remove failed for title non-existent')

print('Serializing notes')
data, checksum = priv_notes.dump()

print('Loading notes')
new_notes_instance = PrivNotes('123456', data, checksum)
for title in kvs:
  note1 = priv_notes.get(title)
  note2 = new_notes_instance.get(title)
  if note1 != note2:
    error('get mismatch for title %s (received values %s and %s)' % (title, note1, note2))

print('Testing complete')
