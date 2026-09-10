# frozen_string_literal: true

module Api
  class TemplatesSubmissionsExportController < ApiBaseController
    load_and_authorize_resource :template
    load_and_authorize_resource :submission, through: :template, parent: false

    def index
      submissions = @submissions.active
                                .preload(submitters: { documents_attachments: :blob,
                                                       attachments_attachments: :blob })
                                .order(id: :asc)

      submissions = Submissions.search(current_user, submissions, params[:q], search_values: true)
      submissions = Submissions::Filter.call(submissions, current_user, params)

      requested_format = params[:format].presence || request.query_parameters['format']
      format = requested_format == 'csv' ? 'csv' : 'xlsx'
      expires_at = Accounts.link_expires_at(current_account)

      content_type =
        if format == 'csv'
          'text/csv'
        else
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        end

      send_data Submissions::GenerateExportFiles.call(submissions, format:, expires_at:),
                filename: "#{@template.name}.#{format}",
                type: content_type
    end
  end
end
