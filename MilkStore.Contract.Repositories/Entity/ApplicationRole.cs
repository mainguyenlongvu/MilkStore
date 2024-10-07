using Microsoft.AspNetCore.Identity;
using MilkStore.Core.Utils;

namespace MilkStore.Contract.Repositories.Entity
{
    public class ApplicationRole : IdentityRole<Guid>
    {
        public string? CreatedBy { get; set; }
        public string? LastUpdatedBy { get; set; }
        public string? DeletedBy { get; set; }
        public DateTimeOffset CreatedTime { get; set; }
        public DateTimeOffset LastUpdatedTime { get; set; }
        public DateTimeOffset? DeletedTime { get; set; }
        public virtual ICollection<ApplicationUserRoles> UserRoles { get; set; } = new List<ApplicationUserRoles>();
        public ApplicationRole()
        {
            CreatedTime = CoreHelper.SystemTimeNow;
            LastUpdatedTime = CreatedTime;
        }
    }
}