import React, { useCallback, useMemo, useState } from 'react'
import Editor from '@draft-js-plugins/editor'
import createMentionPlugin, { MentionData } from '@draft-js-plugins/mention'
import createLinkifyPlugin from '@draft-js-plugins/linkify'
import {
  convertFromRaw,
  EditorState,
  getDefaultKeyBinding,
  KeyBindingUtil,
  DraftHandleValue,
  RichUtils,
} from 'draft-js'
import { mdToDraftjs } from 'draftjs-md-converter'
import 'draft-js/dist/Draft.css'
import { Entry, useAutoCompleteQuery } from '../../../generated/graphql'
import '@draft-js-plugins/mention/lib/plugin.css'
import { logMarkdown } from './markdown'
import { EditMenu } from './editor-menu'

const { hasCommandModifier } = KeyBindingUtil

const keyBinding = () => (e: React.KeyboardEvent): string | null => {
  if (e.keyCode === 83 /* `S` key */ && hasCommandModifier(e)) {
    return 'editor-save'
  }
  return getDefaultKeyBinding(e)
}

function suggestionsFilter(searchValue: string, suggestions: MentionData[]) {
  const value = searchValue.toLowerCase()
  const filteredSuggestions = suggestions.filter(function (suggestion) {
    return !value || suggestion.name.toLowerCase().indexOf(value) > -1
  })
  const length =
    filteredSuggestions.length < 15 ? filteredSuggestions.length : 15
  return filteredSuggestions.slice(0, length)
}

export function EditorView({ item }: { item: Entry }) {
  const data = useAutoCompleteQuery({
    fetchPolicy: 'cache-and-network',
  }).data
  const hashtags = data?.hashtags.map((tag: string) => {
    return { name: tag } as MentionData
  })
  const mentions = data?.mentions.map((tag: string) => {
    return { name: tag } as MentionData
  })

  const [editorState, setEditorState] = useState(() =>
    EditorState.createWithContent(
      convertFromRaw(mdToDraftjs(item.md || item.text || '')),
    ),
  )
  const [hashtagSuggestions, setHashtagSuggestions] = useState(hashtags)
  const [mentionSuggestions, setMentionSuggestions] = useState(mentions)
  const [hashtagsOpen, setHashtagsOpen] = useState(false)
  const [mentionsOpen, setMentionsOpen] = useState(false)
  const [stateKeyBinding, setStateKeyBinding] = useState(keyBinding)

  const { HashtagSuggestions, MentionSuggestions, plugins } = useMemo(() => {
    const linkifyPlugin = createLinkifyPlugin()
    const hashtagPlugin = createMentionPlugin({ mentionTrigger: '#' })
    const mentionPlugin = createMentionPlugin({ mentionTrigger: '@' })
    const HashtagSuggestions = hashtagPlugin.MentionSuggestions
    const { MentionSuggestions } = mentionPlugin
    const plugins = [hashtagPlugin, linkifyPlugin, mentionPlugin]
    return { plugins, HashtagSuggestions, MentionSuggestions }
  }, [])

  function handleKeyCommand(command: string): DraftHandleValue {
    const newState = RichUtils.handleKeyCommand(editorState, command)

    if (newState) {
      setEditorState(newState)
      return 'handled'
    }

    if (command === 'editor-save') {
      logMarkdown(editorState)
      return 'handled'
    }
    return 'not-handled'
  }

  function onHashtagSearchChange({ value }: { value: string }) {
    setHashtagSuggestions(suggestionsFilter(value, hashtags))
  }

  function onMentionSearchChange({ value }: { value: string }) {
    setMentionSuggestions(suggestionsFilter(value, mentions))
  }

  const onHashtagsOpenChange = useCallback((_open: boolean) => {
    if (_open) {
      setStateKeyBinding(undefined)
    } else {
      setStateKeyBinding(keyBinding)
    }
    setHashtagsOpen(_open)
  }, [])

  const onMentionsOpenChange = useCallback((_open: boolean) => {
    if (_open) {
      setStateKeyBinding(undefined)
    } else {
      setStateKeyBinding(keyBinding)
    }
    setMentionsOpen(_open)
  }, [])

  return (
    <div className="entry-text">
      <EditMenu editorState={editorState} setEditorState={setEditorState} />
      <Editor
        editorState={editorState}
        onChange={setEditorState}
        placeholder=""
        // @ts-ignore
        keyBindingFn={stateKeyBinding}
        handleKeyCommand={handleKeyCommand}
        plugins={plugins}
      />
      {hashtagSuggestions && (
        <HashtagSuggestions
          onSearchChange={onHashtagSearchChange}
          suggestions={hashtagSuggestions}
          onOpenChange={onHashtagsOpenChange}
          open={hashtagsOpen}
        />
      )}
      {mentionSuggestions && (
        <MentionSuggestions
          onSearchChange={onMentionSearchChange}
          suggestions={mentionSuggestions}
          onOpenChange={onMentionsOpenChange}
          open={mentionsOpen}
        />
      )}
    </div>
  )
}
