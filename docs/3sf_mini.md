# 3SF-mini

TODO: add 3SF-mini explanation

## Justifiable Slot Backoff

The 3SF-mini algorithm introduces a backoff mechanism to increase finalization rate during periods of asynchrony.
This is achieved by "diluting" the possible targets of a justification vote, through the `slot_is_justifiable_after` function (`Slot.is_justifiable_after` in the spec).
The function marks only some slots as valid justification targets, with the distance between them increasing over time since the last finalization.
This increases the period during which votes for a given slot can be included, improving the chances of achieving the required 2/3 majority for justification.
Also, since two consecutive justified **justifiable** slots are needed to finalized a slot, this backoff isn't immediately reset after finalization occurs, only lowering over time when synchrony is restored.

As an example, consider this scenario:

- The last finalized slot is 0.
- Slot 1 is justified.
- During the next 14 slots (2 to 15), only some votes with differing targets are included, so no new justification occurs.
- At slots 16, 17, 18, and 19, the last justifiable slot is 16, so enough votes are included to justify slot 16 (with slot 1 as source).
  - Since there are multiple justifiable slots between 1 and 16, slot 1 isn't finalized yet.
- Slot 20 is reached, and in the following slots, enough votes are included to justify it, with slot 16 as source.
  - Since slots 16 and 20 are consecutive justifiable slots, slot 16 is now finalized (and past slots too).
  - The backoff is effectively reduced, since the next justifiable slots after 20 are 21, 22, 25, 28, and so on.
