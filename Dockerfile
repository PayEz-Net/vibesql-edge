FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY KeelBase.Edge/KeelBase.Edge.csproj KeelBase.Edge/
RUN dotnet restore KeelBase.Edge/KeelBase.Edge.csproj

COPY KeelBase.Edge/ KeelBase.Edge/
RUN dotnet publish KeelBase.Edge/KeelBase.Edge.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app
EXPOSE 5100

# Required environment variables:
#   ConnectionStrings__EdgeDb - PostgreSQL connection string
#   KeelBase__PublicApiUrl - Upstream Public API URL
#   KeelBase__UpstreamAuthMode - Auth mode
#   KeelBase__HmacSecret - HMAC secret
#   KeelBase__ContainerSecret - Container secret

ENV ASPNETCORE_URLS=http://+:5100
ENV DOTNET_RUNNING_IN_CONTAINER=true

COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "KeelBase.Edge.dll"]
