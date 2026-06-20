<template>
  <label
    v-if="showFieldNames && (field.name || field.title)"
    :for="field.uuid"
    dir="auto"
    class="label text-xl sm:text-2xl py-0 mb-2 sm:mb-3.5 field-name-label"
    :class="{ 'mb-2': !field.description }"
  >
    <MarkdownContent
      v-if="field.title"
      :string="field.title"
    />
    <template v-else>{{ field.name }}</template>
    <template v-if="!field.required">
      <span :class="{ 'hidden sm:inline': (field.title || field.name).length > 20 }">
        ({{ t('optional') }})
      </span>
    </template>
  </label>
  <div
    v-else
    class="py-1"
  />
  <div
    v-if="field.description"
    dir="auto"
    class="mb-3 px-1 field-description-text"
  >
    <MarkdownContent :string="field.description" />
  </div>
  <AppearsOn :field="field" />
  <div class="relative w-full">
    <textarea
      :id="field.uuid"
      ref="textarea"
      v-model="text"
      dir="auto"
      rows="1"
      class="base-textarea !text-2xl w-full !pr-12 min-h-[3.25rem] resize-none overflow-hidden"
      :required="field.required"
      :pattern="field.validation?.pattern"
      :placeholder="`${t('speak_or_type_here_')}${field.required ? '' : ` (${t('optional')})`}`"
      :name="`values[${field.uuid}]`"
      @invalid="validationMessage ? $event.target.setCustomValidity(validationMessage) : ''"
      @input="onInput"
      @focus="$emit('focus')"
    />
    <div
      v-if="speechSupported"
      class="tooltip absolute right-1 top-1/2 -translate-y-1/2"
      :data-tip="isListening ? t('stop_listening') : t('start_voice_input')"
    >
      <button
        type="button"
        class="btn btn-ghost btn-circle btn-sm voice-input-button"
        :class="{ 'btn-active text-error': isListening }"
        @click.prevent="toggleListening"
      >
        <IconMicrophone />
      </button>
    </div>
  </div>
  <div
    v-if="withVoice && text.trim().length > 0"
    class="mt-3 flex justify-end"
  >
    <button
      type="button"
      class="btn btn-sm btn-outline voice-summarize-button"
      :disabled="isSummarizing"
      @click.prevent="summarize"
    >
      <span v-if="isSummarizing">{{ t('voice_summarizing') }}</span>
      <span v-else>{{ t('voice_summarize') }}</span>
    </button>
  </div>
  <p
    v-if="isListening"
    class="text-sm text-base-content/60 mt-2 px-1"
  >
    {{ t('listening_') }}
  </p>
  <p
    v-else-if="!speechSupported"
    class="text-sm text-base-content/60 mt-2 px-1"
  >
    {{ t('voice_input_not_supported') }}
  </p>
  <p
    v-if="summarizeError"
    class="text-sm text-error mt-2 px-1"
  >
    {{ summarizeError }}
  </p>
  <div
    v-if="withVoice && summary"
    class="mt-3 rounded-3xl border border-base-300 bg-base-200/40 p-4"
  >
    <div class="text-sm font-medium uppercase text-base-content/60 mb-2">
      {{ t('voice_summary') }}
    </div>
    <p
      dir="auto"
      class="text-lg whitespace-pre-wrap"
    >
      {{ summary }}
    </p>
    <div
      v-if="tokenInfo"
      class="mt-3 flex gap-4 text-xs text-base-content/60 border-t border-base-300 pt-3"
    >
      <span>Used: <strong>{{ tokenInfo.used_token?.toLocaleString() }}</strong></span>
      <span>Remaining: <strong>{{ tokenInfo.remaining_token?.toLocaleString() }}</strong></span>
      <span>Total: <strong>{{ tokenInfo.fixed_token?.toLocaleString() }}</strong></span>
    </div>
    <div class="mt-3 flex justify-end">
      <button
        type="button"
        class="btn btn-sm btn-neutral text-white voice-use-summary-button"
        @click.prevent="applySummary"
      >
        {{ t('voice_use_summary') }}
      </button>
    </div>
  </div>
</template>

<script>
import { IconMicrophone } from '@tabler/icons-vue'
import AppearsOn from './appears_on'
import MarkdownContent from './markdown_content'

export default {
  name: 'VoiceStep',
  components: {
    IconMicrophone,
    MarkdownContent,
    AppearsOn
  },
  inject: ['t', 'baseUrl', 'withVoice'],
  props: {
    field: {
      type: Object,
      required: true
    },
    showFieldNames: {
      type: Boolean,
      required: false,
      default: true
    },
    modelValue: {
      type: String,
      required: false,
      default: ''
    },
    submitterSlug: {
      type: String,
      required: false,
      default: ''
    }
  },
  emits: ['update:model-value', 'focus'],
  data () {
    return {
      isListening: false,
      recognition: null,
      isSummarizing: false,
      summary: '',
      tokenInfo: null,
      summarizeError: '',
      shouldSummarizeOnStop: false
    }
  },
  computed: {
    speechSupported () {
      return !!(window.SpeechRecognition || window.webkitSpeechRecognition)
    },
    lengthValidation () {
      if (this.field.validation?.pattern) {
        return this.field.validation.pattern.match(/^\.{(?<min>\d+),(?<max>\d+)?}$/)?.groups
      } else {
        return null
      }
    },
    validationMessage () {
      if (this.field.validation?.message) {
        return this.field.validation.message
      } else if (this.lengthValidation) {
        const number =
          [this.lengthValidation.min, this.lengthValidation.max]
            .filter(Boolean)
            .filter((v, i, a) => a.indexOf(v) === i)
            .join('-')

        return this.t('must_be_characters_length').replace('{number}', number)
      } else {
        return ''
      }
    },
    text: {
      set (value) {
        this.$emit('update:model-value', value)
      },
      get () {
        return this.modelValue
      }
    }
  },
  watch: {
    modelValue () {
      this.$nextTick(() => {
        this.resizeTextarea()
      })
    }
  },
  mounted () {
    if (this.modelValue) {
      this.$nextTick(() => {
        this.resizeTextarea()
      })
    }
  },
  beforeUnmount () {
    this.stopListening()
  },
  methods: {
    onInput (event) {
      if (this.validationMessage) {
        event.target.setCustomValidity('')
      }

      this.summary = ''
      this.tokenInfo = null
      this.summarizeError = ''
      this.resizeTextarea()
    },
    resizeTextarea () {
      const textarea = this.$refs.textarea

      if (textarea) {
        textarea.style.height = 'auto'
        textarea.style.height = Math.min(250, textarea.scrollHeight) + 'px'
      }
    },
    applySummary () {
      if (!this.summary) {
        return
      }

      this.text = this.summary

      this.$nextTick(() => {
        this.resizeTextarea()
      })
    },
    async summarize () {
      const text = this.text.trim()

      if (!text || this.isSummarizing) {
        return
      }

      this.isSummarizing = true
      this.summarizeError = ''
      this.summary = ''
      this.tokenInfo = null

      try {
        const response = await fetch(`${this.baseUrl}/api/voice_summarize`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            text,
            submitter_slug: this.submitterSlug
          })
        })

        const data = await response.json()

        if (!response.ok) {
          throw new Error(data.error || this.t('voice_summarize_failed'))
        }

        this.summary = data.summary
        this.tokenInfo = data.quota || null
      } catch (error) {
        this.summarizeError = error.message || this.t('voice_summarize_failed')
      } finally {
        this.isSummarizing = false
      }
    },
    toggleListening () {
      if (this.isListening) {
        this.stopListening()
      } else {
        this.startListening()
      }
    },
    startListening () {
      const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition

      if (!SpeechRecognition) {
        return
      }

      this.shouldSummarizeOnStop = false

      this.recognition = new SpeechRecognition()
      this.recognition.continuous = true
      this.recognition.interimResults = true
      this.recognition.lang = document.documentElement.lang || navigator.language || 'en-US'

      this.recognition.onresult = (event) => {
        let transcript = ''

        for (let i = event.resultIndex; i < event.results.length; i++) {
          if (event.results[i].isFinal) {
            transcript += event.results[i][0].transcript
          }
        }

        if (transcript) {
          const separator = this.text && !this.text.endsWith(' ') ? ' ' : ''

          this.text = `${this.text}${separator}${transcript.trim()}`
          this.shouldSummarizeOnStop = true

          this.$nextTick(() => {
            this.resizeTextarea()
          })
        }
      }

      this.recognition.onerror = () => {
        this.stopListening()
      }

      this.recognition.onend = () => {
        this.stopListening()
      }

      this.recognition.start()
      this.isListening = true
      this.$emit('focus')
    },
    stopListening () {
      const shouldAutoSummarize = this.shouldSummarizeOnStop && this.withVoice && this.text.trim().length >= 20

      if (this.recognition) {
        this.recognition.onresult = null
        this.recognition.onerror = null
        this.recognition.onend = null

        try {
          this.recognition.stop()
        } catch {}

        this.recognition = null
      }

      this.isListening = false
      this.shouldSummarizeOnStop = false

      if (shouldAutoSummarize) {
        this.summarize()
      }
    }
  }
}
</script>
