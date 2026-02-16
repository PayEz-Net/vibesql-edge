FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY Vibe.Edge/Vibe.Edge.csproj Vibe.Edge/
RUN dotnet restore Vibe.Edge/Vibe.Edge.csproj

COPY Vibe.Edge/ Vibe.Edge/
RUN dotnet publish Vibe.Edge/Vibe.Edge.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app
EXPOSE 5100

# Required environment variables:
#   ConnectionStrings__EdgeDb     - PostgreSQL connection string
#   VibeEdge__PublicApiUrl        - Upstream VibeSQL Public API URL
#   VibeEdge__AdminApiKey         - Admin API key for /v1/admin/* endpoints

ENV ASPNETCORE_URLS=http://+:5100
ENV DOTNET_RUNNING_IN_CONTAINER=true

COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "Vibe.Edge.dll"]
